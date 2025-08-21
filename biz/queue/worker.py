import os
import traceback
from datetime import datetime

from biz.entity.review_entity import MergeRequestReviewEntity, PushReviewEntity
from biz.event.event_manager import event_manager
from biz.gitlab.webhook_handler import (
    filter_changes, filter_diffs_by_file_types, preprocessing_diffs, MergeRequestHandler, PushHandler
)
from biz.github.webhook_handler import (
    filter_changes as filter_github_changes, PullRequestHandler as GithubPullRequestHandler, PushHandler as GithubPushHandler
)
from biz.utils.code_reviewer import CodeReviewer
from biz.utils.im import notifier
from biz.utils.log import logger



def handle_push_event(webhook_data: dict, gitlab_token: str, gitlab_url: str, gitlab_url_slug: str):
    push_review_enabled = os.environ.get('PUSH_REVIEW_ENABLED', '0') == '1'
    try:
        handler = PushHandler(webhook_data, gitlab_token, gitlab_url)
        logger.info('Push Hook event received')
        commits = handler.get_push_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        review_result = None
        score = 0
        additions = 0
        deletions = 0
        if push_review_enabled:
            # 获取PUSH的changes
            changes = handler.get_push_changes()
            logger.info('changes: %s', changes)
            changes = filter_changes(changes)
            if not changes:
                logger.info('未检测到PUSH代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            review_result = "关注的文件没有修改"

            if len(changes) > 0:
                commits_text = ';'.join(commit.get('message', '').strip() for commit in commits)
                review_result = CodeReviewer().review_and_strip_code(changes, commits_text, changes)
                score = CodeReviewer.parse_review_score(review_text=review_result)
                for item in changes:
                    additions += item['additions']
                    deletions += item['deletions']
            # 将review结果提交到Gitlab的 notes
            handler.add_push_notes(f'Auto Review Result: \n{review_result}')

        event_manager['push_reviewed'].send(PushReviewEntity(
            project_name=webhook_data['project']['name'],
            author=webhook_data['user_username'],
            branch=webhook_data['project']['default_branch'],
            updated_at=int(datetime.now().timestamp()),  # 当前时间
            commits=commits,
            score=score,
            review_result=review_result,
            url_slug=gitlab_url_slug,
            webhook_data=webhook_data,
            additions=additions,
            deletions=deletions,
        ))

    except Exception as e:
        error_message = f'服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)


def handle_merge_request_event(webhook_data: dict, gitlab_token: str, gitlab_url: str, gitlab_url_slug: str):
    '''
    处理Merge Request Hook事件
    :param webhook_data:
    :param gitlab_token:
    :param gitlab_url:
    :param gitlab_url_slug:
    :return:
    '''
    merge_review_only_protected_branches = os.environ.get('MERGE_REVIEW_ONLY_PROTECTED_BRANCHES_ENABLED', '0') == '1'
    try:
        # 解析Webhook数据
        handler = MergeRequestHandler(webhook_data, gitlab_token, gitlab_url)
        logger.info('Merge Request Hook event received')
        # 如果开启了仅review projected branches的，判断当前目标分支是否为projected branches
        if merge_review_only_protected_branches and not handler.target_branch_protected():
            logger.info("Merge Request target branch not match protected branches, ignored.")
            return

        # 'updated' 状态的 MR 也先不处理，否则会重复review和评论
        if handler.action not in ['opened', 'reopened']:
            logger.info(f"Merge Request Hook event, action={handler.action}, ignored.")
            return

        # 仅仅在MR创建或更新时进行Code Review
        # 获取Merge Request的changes -> GitLab 15.7 废弃changes接口，直接使用diffs接口
        # diffs 在当前项目环境有点问题，获取不到数据，未查明根因，使用 get_merge_request_diffs_from_base_sha_to_head_sha 替代
        diffs = handler.get_merge_request_diffs_from_base_sha_to_head_sha()
        logger.info('diffs: %s', diffs)
        diffs_with_filter = filter_changes(diffs)
        logger.info('diffs with filter: %s', diffs_with_filter)
        if not diffs_with_filter:
            logger.info('未检测到有关代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            return
        # 统计本次新增、删除的代码总数
        additions = 0
        deletions = 0
        for item in diffs_with_filter:
            additions += item.get('additions', 0)
            deletions += item.get('deletions', 0)

        # 获取Merge Request的commits
        commits = handler.get_merge_request_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        # review 代码
        commits_text = ';'.join(commit['title'] for commit in commits)
        logger.info('commits text: %s', commits_text)
        review_result = CodeReviewer().review_and_strip_code(diffs_with_filter, commits_text, diffs)

        # 将review结果提交到Gitlab的 notes
        handler.add_merge_request_notes(f'Auto Review Result: \n{review_result}')

        # dispatch merge_request_reviewed event
        event_manager['merge_request_reviewed'].send(
            MergeRequestReviewEntity(
                project_name=webhook_data['project']['name'],
                author=webhook_data['user']['username'],
                source_branch=webhook_data['object_attributes']['source_branch'],
                target_branch=webhook_data['object_attributes']['target_branch'],
                updated_at=int(datetime.now().timestamp()),
                commits=commits,
                score=CodeReviewer.parse_review_score(review_text=review_result),
                url=webhook_data['object_attributes']['url'],
                review_result=review_result,
                url_slug=gitlab_url_slug,
                webhook_data=webhook_data,
                additions=additions,
                deletions=deletions,
            )
        )

    except Exception as e:
        error_message = f'AI Code Review 服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)

# 原方法是添加评论到MR外层，需要修改为添加评论到具体的变更代码行
# 并且需要修改 review 的语料
# 因此直接copy了一份 handle_merge_request_event 方法进行修改
def handle_merge_request_event_v2(webhook_data: dict, gitlab_token: str, gitlab_url: str, gitlab_url_slug: str):
    '''
    处理Merge Request Hook事件
    :param webhook_data:
    :param gitlab_token:
    :param gitlab_url:
    :param gitlab_url_slug:
    :return:

    v2:
    1. 原整个diffs进行review，现拆分为单个diff+diffs+file进行review
    2. 原添加review的评论到MR外层，现添加到具体的变更代码行
    '''
    merge_review_only_protected_branches = os.environ.get('MERGE_REVIEW_ONLY_PROTECTED_BRANCHES_ENABLED', '0') == '1'
    try:
        # 解析Webhook数据
        handler = MergeRequestHandler(webhook_data, gitlab_token, gitlab_url)
        logger.info('Merge Request Hook event received')
        # 如果开启了仅review projected branches的，判断当前目标分支是否为projected branches
        if merge_review_only_protected_branches and not handler.target_branch_protected():
            logger.info("Merge Request target branch not match protected branches, ignored.")
            return

        # 'updated' 状态的 MR 也先不处理，否则会重复review和评论
        if handler.action not in ['opened', 'reopened']:
            logger.info(f"Merge Request Hook event, action={handler.action}, ignored.")
            return

        # 获取 MR 的 commits 信息
        commits = handler.get_merge_request_commits()
        if not commits:
            logger.error('Failed to get commits')
            return
        commits_text = ';'.join(commit['title'] for commit in commits)
        logger.info('commits text: %s', commits_text)

        # 仅仅在MR创建或更新时进行Code Review
        diffs = handler.get_merge_request_changes()
        logger.info('origin diffs: %s', diffs)

        # 过滤掉不 review 的文件类型
        diffs = filter_diffs_by_file_types(diffs)
        logger.info("filter file type diffs: %s", diffs)

        # 将diffs拆为每个改动点为一个diff
        diffs = preprocessing_diffs(diffs) # 重新赋值修改新的diffs
        logger.info("split diffs: %s", diffs)

        # 获取 sha: head_sha, base_sha, start_sha，用于定位行内评论的位置
        sha = handler.get_merge_request_sha()
        # 0. 对每一个改动点进行语料补充，并提交ai review
        for diff in diffs:
            # 1. 提取文件路径、行号用于添加评论
            old_path = diff.get("old_path")
            new_path = diff.get("new_path")
            old_line, new_line = extract_line_numbers(diff) # 获取添加评论的行号

            # 2. 判断是否为新增文件，如果是新增的文件，则不需要传入diffs、file_content，因为diff就是完整内容
            if diff.get("new_file") == True or diff.get("new_file") == "true":
                diffs_tmp, file_content_tmp = "当前diff为新增文件", "当前diff为新增文件"
            else:
                file_content = handler.get_gitlab_file_content(branch_type="source_branch", file_path=new_path) # 获取修改后的完整文件内容
                diffs_tmp, file_content_tmp = diffs, file_content
            
            # 3. 对获取到的diff文件做限制，如过滤文件大小、截断 【待完成，当前使用token做了限制】

            # 4. 分析文件内容对应的token，如果超过限制，则取改动点前后 500 行的代码作为上下文传递给 ai，大概是 8-10k token
            file_tokens_count = CodeReviewer().count_tokens(text=file_content_tmp)
            if file_tokens_count >= 10000:
                logger.debug(f"当前文件tokens为: {file_tokens_count}，超过限制的10k token, 截取改动点前后500行代码作为上下文")
                file_content_tmp = extract_surrounding_lines(text=file_content, line_number=new_line, context_line_num=500)

            # 5. 将单个 prompt: diff + file content 发到 ai review
            review_result = CodeReviewer().review_code_simple(diff, diffs_tmp, file_content_tmp)

            # 6. 添加评论
            handler.add_merge_request_discussions_on_row(
                content=review_result,
                base_sha=sha["base_sha"],
                head_sha=sha["head_sha"],
                start_sha=sha["start_sha"],
                old_path=old_path,
                new_path=new_path,
                old_line=old_line,
                new_line=new_line
            )
        logger.info(f"Merge Request ai code review all done, its commits: {commits}!")

        # 结果统计到数据库
        # 统计本次新增、删除的代码总数
        additions = 0
        deletions = 0
        for item in diffs:
            additions += item.get('additions', 0)
            deletions += item.get('deletions', 0)

        # dispatch merge_request_reviewed event
        event_manager['merge_request_reviewed'].send(
            MergeRequestReviewEntity(
                project_name=webhook_data['project']['name'],
                author=webhook_data['user']['username'],
                source_branch=webhook_data['object_attributes']['source_branch'],
                target_branch=webhook_data['object_attributes']['target_branch'],
                updated_at=int(datetime.now().timestamp()),
                commits=commits,
                score=CodeReviewer.parse_review_score(review_text=review_result),
                url=webhook_data['object_attributes']['url'],
                review_result=review_result,
                url_slug=gitlab_url_slug,
                webhook_data=webhook_data,
                additions=additions,
                deletions=deletions,
            )
        )

    except Exception as e:
        error_message = f'AI Code Review 服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)



def handle_github_push_event(webhook_data: dict, github_token: str, github_url: str, github_url_slug: str):
    push_review_enabled = os.environ.get('PUSH_REVIEW_ENABLED', '0') == '1'
    try:
        handler = GithubPushHandler(webhook_data, github_token, github_url)
        logger.info('GitHub Push event received')
        commits = handler.get_push_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        review_result = None
        score = 0
        additions = 0
        deletions = 0
        if push_review_enabled:
            # 获取PUSH的changes
            changes = handler.get_push_changes()
            logger.info('changes: %s', changes)
            changes = filter_github_changes(changes)
            if not changes:
                logger.info('未检测到PUSH代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            review_result = "关注的文件没有修改"

            if len(changes) > 0:
                commits_text = ';'.join(commit.get('message', '').strip() for commit in commits)
                review_result = CodeReviewer().review_and_strip_code(changes, commits_text, changes)
                score = CodeReviewer.parse_review_score(review_text=review_result)
                for item in changes:
                    additions += item.get('additions', 0)
                    deletions += item.get('deletions', 0)
            # 将review结果提交到GitHub的 notes
            handler.add_push_notes(f'Auto Review Result: \n{review_result}')

        event_manager['push_reviewed'].send(PushReviewEntity(
            project_name=webhook_data['repository']['name'],
            author=webhook_data['sender']['login'],
            branch=webhook_data['ref'].replace('refs/heads/', ''),
            updated_at=int(datetime.now().timestamp()),  # 当前时间
            commits=commits,
            score=score,
            review_result=review_result,
            url_slug=github_url_slug,
            webhook_data=webhook_data,
            additions=additions,
            deletions=deletions,
        ))

    except Exception as e:
        error_message = f'服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)


def handle_github_pull_request_event(webhook_data: dict, github_token: str, github_url: str, github_url_slug: str):
    '''
    处理GitHub Pull Request 事件
    :param webhook_data:
    :param github_token:
    :param github_url:
    :param github_url_slug:
    :return:
    '''
    merge_review_only_protected_branches = os.environ.get('MERGE_REVIEW_ONLY_PROTECTED_BRANCHES_ENABLED', '0') == '1'
    try:
        # 解析Webhook数据
        handler = GithubPullRequestHandler(webhook_data, github_token, github_url)
        logger.info('GitHub Pull Request event received')
        # 如果开启了仅review projected branches的，判断当前目标分支是否为projected branches
        if merge_review_only_protected_branches and not handler.target_branch_protected():
            logger.info("Merge Request target branch not match protected branches, ignored.")
            return

        if handler.action not in ['opened', 'synchronize']:
            logger.info(f"Pull Request Hook event, action={handler.action}, ignored.")
            return

        # 仅仅在PR创建或更新时进行Code Review
        # 获取Pull Request的changes
        changes = handler.get_pull_request_changes()
        logger.info('changes: %s', changes)
        changes = filter_github_changes(changes)
        if not changes:
            logger.info('未检测到有关代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            return
        # 统计本次新增、删除的代码总数
        additions = 0
        deletions = 0
        for item in changes:
            additions += item.get('additions', 0)
            deletions += item.get('deletions', 0)

        # 获取Pull Request的commits
        commits = handler.get_pull_request_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        # review 代码
        commits_text = ';'.join(commit['title'] for commit in commits)
        review_result = CodeReviewer().review_and_strip_code(changes, commits_text, changes)

        # 将review结果提交到GitHub的 notes
        handler.add_pull_request_notes(f'Auto Review Result: \n{review_result}')

        # dispatch pull_request_reviewed event
        event_manager['merge_request_reviewed'].send(
            MergeRequestReviewEntity(
                project_name=webhook_data['repository']['name'],
                author=webhook_data['pull_request']['user']['login'],
                source_branch=webhook_data['pull_request']['head']['ref'],
                target_branch=webhook_data['pull_request']['base']['ref'],
                updated_at=int(datetime.now().timestamp()),
                commits=commits,
                score=CodeReviewer.parse_review_score(review_text=review_result),
                url=webhook_data['pull_request']['html_url'],
                review_result=review_result,
                url_slug=github_url_slug,
                webhook_data=webhook_data,
                additions=additions,
                deletions=deletions,
            ))

    except Exception as e:
        error_message = f'服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)


def extract_line_numbers(diff_entry):
    """
    从GitLab API返回的diff条目提取old_line和new_line行号
    判断条件：
        1. 如果是删除文件，返回old_line=删除的起始行，new_line=None
        2. 如果是新增文件，返回old_line=None，new_line=新增的起始行
        3. 如果是修改文件，同时返回old_line=原起始行, new_line=新起始行，表示修改的地方
    
    参数:
        diff_entry: 包含diff信息的字典，需包含'diff'键
        
    返回:
        元组(old_line, new_line)，若无法解析则返回(None, None)

    注意：
        这里一定要是单个文件单个改动的才能提取到正确的行号，需经过 filter_diffs_by_file_types() 方法预处理
    """
    diff_content = diff_entry.get('diff', '')
    if not diff_content:
        return None, None
    
    # 查找包含行号信息的@@标记行
    lines = diff_content.split('\n')
    for line in lines:
        if line.startswith('@@') and '@@' in line[2:]:
            # 提取@@之间的内容，例如: -30,7 +30,7
            line_info = line.split('@@')[1].strip()
            
            # 分割旧行和新行信息
            parts = line_info.split()
            if len(parts) != 2:
                continue
                
            old_part, new_part = parts
            
            # 解析旧行号信息 (格式: -开始行,行数)
            old_start = old_part[1:].split(',')[0] if ',' in old_part else old_part[1:]
            # 解析新行号信息 (格式: +开始行,行数)
            new_start = new_part[1:].split(',')[0] if ',' in new_part else new_part[1:]
            
            # 判断文件操作类型并返回对应行号
            # 新增文件: 原文件无内容(-0,0)
            if old_start == '0':
                return None, int(new_start) if new_start.isdigit() else None
            # 删除文件: 新文件无内容(+0,0)
            elif new_start == '0':
                return int(old_start) if old_start.isdigit() else None, None
            # 修改文件: 正常返回新旧行号
            else:
                return (int(old_start) if old_start.isdigit() else None,
                        int(new_start) if new_start.isdigit() else None)
    
    # 如果没有找到有效的行号信息
    return None, None


def extract_surrounding_lines(text, line_number: int, context_line_num: int = 50):
    """
    提取文本中指定行前后指定行的内容（默认50）
    
    参数:
        text: 原始文本内容（通常来自requests.get().text）
        line_number: 目标行号（从1开始计数）
        
    返回:
        包含目标行前后50行内容的字符串，每行保留原始换行符
    """
    # 将文本按行分割，保留空行
    lines = text.splitlines(keepends=True)
    
    # 验证行号有效性
    total_lines = len(lines)
    if line_number < 1 or line_number > total_lines:
        raise ValueError(f"行号超出范围，有效行号为1到{total_lines}")
    
    # 计算起始行和结束行
    start = max(0, line_number - 1 - context_line_num)
    end = min(total_lines, line_number + context_line_num)
    
    # 提取对应范围的行并合并
    return ''.join(lines[start:end])