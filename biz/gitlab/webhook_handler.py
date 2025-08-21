import json
import os
import re
import time
from urllib.parse import urljoin
import fnmatch
import requests

from biz.utils.log import logger
from typing import Optional, Dict
from flask import Flask, request, jsonify

def filter_changes(changes: list):
    '''
    过滤数据，只保留支持的文件类型以及必要的字段信息
    diffs、changes接口返回的列表通用
    '''
    # 从环境变量中获取支持的文件扩展名
    supported_extensions = os.getenv('SUPPORTED_EXTENSIONS', '.java,.py,.php').split(',')

    filter_deleted_files_changes = [change for change in changes if not change.get("deleted_file")]

    # 过滤 `new_path` 以支持的扩展名结尾的元素, 仅保留diff和new_path字段
    filtered_changes = [
        {
            'diff': item.get('diff', ''),
            'new_path': item['new_path'],
            'additions': len(re.findall(r'^\+(?!\+\+)', item.get('diff', ''), re.MULTILINE)),
            'deletions': len(re.findall(r'^-(?!--)', item.get('diff', ''), re.MULTILINE))
        }
        for item in filter_deleted_files_changes
        if any(item.get('new_path', '').endswith(ext) for ext in supported_extensions)
    ]
    return filtered_changes

def filter_diffs_by_file_types(diffs: list):
    '''
    过滤数据，只保留支持的文件类型，保留所有字段信息
    diffs、changes接口返回的列表通用
    '''
    # 从环境变量中获取支持的文件扩展名
    supported_extensions = os.getenv('SUPPORTED_EXTENSIONS', '.java,.py,.php').split(',')

    # 过滤掉已删除的文件
    filter_deleted_files_diff = [diff for diff in diffs if not diff.get("deleted_file")]

    # 只过滤文件类型，保留所有字段
    filtered_diffs = [
        item for item in filter_deleted_files_diff
        if any(item.get('new_path', '').endswith(ext) for ext in supported_extensions)
    ]
    
    return filtered_diffs

def slugify_url(original_url: str) -> str:
    """
    将原始URL转换为适合作为文件名的字符串，其中非字母或数字的字符会被替换为下划线，举例：
    slugify_url("http://example.com/path/to/repo/") => example_com_path_to_repo
    slugify_url("https://gitlab.com/user/repo.git") => gitlab_com_user_repo_git
    """
    # Remove URL scheme (http, https, etc.) if present
    original_url = re.sub(r'^https?://', '', original_url)

    # Replace non-alphanumeric characters (except underscore) with underscores
    target = re.sub(r'[^a-zA-Z0-9]', '_', original_url)

    # Remove trailing underscore if present
    target = target.rstrip('_')

    return target

def preprocessing_diffs(original_diffs: list) -> list:
    """
    gitlab api返回的diffs是所有文件的所有改动
    该方法进行：
        1. 文件过滤，将不进行review的文件过滤掉
        2. 将单个文件多个改动点的diff，拆成多个diff
        3. 最终组装为一个diffs进行返回
    """
    result = []
    # 精准匹配diff块结构：
    # @@ 行号信息（如-61,7 +61,7） @@ 函数定义（如def divide_numbers...）
    # 然后匹配所有内容直到下一个@@或结束（包括空行、注释）
    diff_pattern = re.compile(
        r'@@ -?\d+,\d+ [+-]?\d+,\d+ @@.*?(?=@@|$)',  # 核心：匹配完整标记+内容
        re.DOTALL  # 确保.匹配换行符
    )
    
    for item in original_diffs:
        diff_content = item['diff']
        # 提取所有完整diff块
        diff_blocks = diff_pattern.findall(diff_content)
        
        # 过滤空块，保留原始格式（不trim，避免丢失空行）
        valid_blocks = [block for block in diff_blocks if block.strip()]
        
        # 生成拆分后的对象
        for block in valid_blocks:
            new_item = item.copy()
            new_item['diff'] = block  # 保留原始内容（含换行、空格）
            result.append(new_item)
    
    return result

class MergeRequestHandler:
    def __init__(self, webhook_data: dict, gitlab_token: str, gitlab_url: str):
        self.merge_request_iid = None
        self.webhook_data = webhook_data
        self.gitlab_token = gitlab_token
        self.gitlab_url = gitlab_url
        self.event_type = None
        self.project_id = None
        self.action = None
        self.source_branch = None
        self.target_branch = None
        self.parse_event_type()

    def parse_event_type(self):
        # 提取 event_type
        self.event_type = self.webhook_data.get('object_kind', None)
        if self.event_type == 'merge_request':
            self.parse_merge_request_event()

    def parse_merge_request_event(self):
        # 提取 Merge Request 的相关参数
        merge_request = self.webhook_data.get('object_attributes', {})
        self.merge_request_iid = merge_request.get('iid')
        self.project_id = merge_request.get('target_project_id')
        self.action = merge_request.get('state')
        self.source_branch = merge_request.get('source_branch')
        self.target_branch = merge_request.get('target_branch')
        

    def get_merge_request_sha(self) -> Dict[str, str]:
        """
        获取合并请求的相关SHA值（head_sha, base_sha, start_sha）
        
        返回:
            Dict[str, str]: 包含三个SHA值的字典，若获取失败则值为空字符串
        """
        result = {
            "head_sha": "",
            "base_sha": "",
            "start_sha": ""
        }
        
        # 检查事件类型是否支持
        if self.event_type != 'merge_request':
            logger.warning(f"不支持的事件类型: {self.event_type}，仅支持'merge_request'事件")
            return result

        # 配置请求参数
        max_retries = 3
        headers = {'PRIVATE-TOKEN': self.gitlab_token}
        mr_detail_url = f"{self.gitlab_url}/api/v4/projects/{self.project_id}/merge_requests/{self.merge_request_iid}"
        
        # 重试获取MR详情
        for attempt in range(max_retries):
            try:
                logger.info(f"第 {attempt + 1}/{max_retries} 次请求MR详情: {mr_detail_url}")
                # 添加超时控制，防止请求无限阻塞
                mr_response = requests.get(
                    mr_detail_url,
                    headers=headers,
                    timeout=10  # 10秒超时
                )
                mr_response.raise_for_status()  # 触发HTTP错误
                mr_detail = mr_response.json()
                
                # 提取diff_refs信息
                diff_refs = mr_detail.get("diff_refs", {})
                result["base_sha"] = diff_refs.get("base_sha", "")
                result["head_sha"] = diff_refs.get("head_sha", "")
                result["start_sha"] = diff_refs.get("start_sha", "")
                
                # 检查缺失的SHA字段
                missing_fields = [k for k, v in result.items() if not v]
                if not missing_fields:
                    logger.info(f"成功获取MR #{self.merge_request_iid} 的SHA信息")
                    break  # 全部获取成功，退出重试循环
                
                # 部分字段缺失，记录并准备重试
                logger.warning(
                    f"MR #{self.merge_request_iid} 缺失以下SHA字段: {missing_fields}，将重试"
                )
                if attempt < max_retries - 1:
                    sleep_time = 2 **attempt  # 指数退避策略
                    logger.info(f"等待 {sleep_time} 秒后重试")
                    time.sleep(sleep_time)
                    
            except requests.exceptions.HTTPError as e:
                status_code = mr_response.status_code
                logger.error(f"HTTP错误 (状态码: {status_code}): {str(e)}")
                
                # 仅对服务器错误(5xx)和限流(429)进行重试
                if status_code >= 500 or status_code == 429:
                    if attempt < max_retries - 1:
                        sleep_time = 2** attempt
                        logger.info(f"服务器错误，等待 {sleep_time} 秒后重试")
                        time.sleep(sleep_time)
                        continue
                
                # 客户端错误无需重试，直接返回当前结果
                logger.error(f"无法获取MR详情，HTTP错误: {status_code}")
                break
                
            except requests.exceptions.RequestException as e:
                # 处理其他网络请求异常（超时、连接错误等）
                logger.error(f"网络请求异常: {str(e)}")
                if attempt < max_retries - 1:
                    sleep_time = 2 **attempt
                    logger.info(f"网络错误，等待 {sleep_time} 秒后重试")
                    time.sleep(sleep_time)
                    continue
                logger.error("达到最大重试次数，网络异常未解决")
                break
                
            except Exception as e:
                # 处理其他未知异常
                logger.error(f"获取MR信息时发生未知错误: {str(e)}")
                break

        # 最终检查结果完整性
        missing_fields = [k for k, v in result.items() if not v]
        if missing_fields:
            logger.error(
                f"MR #{self.merge_request_iid} 最终缺失SHA字段: {missing_fields} "
                f"(已尝试 {max_retries} 次)"
            )
        
        return result

    def get_merge_request_changes(self) -> list:
        """
        API: GET /projects/:id/merge_requests/:merge_request_iid/changes
        API URL: https://docs.gitlab.com/api/merge_requests/#get-single-mr-diffs
        WARN: This endpoint was deprecated in GitLab 15.7 and is scheduled for removal in API v5. Use the List merge request diffs endpoint instead.
        修改：
            增加'access_raw_diffs=true'参数获取完整的diffs（对于新增文件）
        """
        # 检查是否为 Merge Request Hook 事件
        if self.event_type != 'merge_request':
            logger.warn(f"Invalid event type: {self.event_type}. Only 'merge_request' event is supported now.")
            return []

        # Gitlab merge request changes API可能存在延迟，多次尝试
        max_retries = 3  # 最大重试次数
        retry_delay = 10  # 重试间隔时间（秒）
        for attempt in range(max_retries):
            # 调用 GitLab API 获取 Merge Request 的 changes
            url = urljoin(f"{self.gitlab_url}/",
                          f"api/v4/projects/{self.project_id}/merge_requests/{self.merge_request_iid}/changes?access_raw_diffs=true")
            headers = {
                'PRIVATE-TOKEN': self.gitlab_token
            }
            response = requests.get(url, headers=headers, verify=False)
            logger.debug(
                f"Get changes response from GitLab (attempt {attempt + 1}): {response.status_code}, {response.text}, URL: {url}")

            # 检查请求是否成功
            if response.status_code == 200:
                changes = response.json().get('changes', [])
                if changes:
                    return changes
                else:
                    logger.info(
                        f"Changes is empty, retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries}), URL: {url}")
                    time.sleep(retry_delay)
            else:
                logger.warn(f"Failed to get changes from GitLab (URL: {url}): {response.status_code}, {response.text}")
                return []

        logger.warning(f"Max retries ({max_retries}) reached. Changes is still empty.")
        return []  # 达到最大重试次数后返回空列表

    def get_merge_request_diffs(self) -> list:
        """
        原方法: get_merge_request_changes，相较于原方法修改了获取改动的gitlab api 为 /diffs
        API: GET /projects/:id/merge_requests/:merge_request_iid/diffs
        API URL: https://docs.gitlab.com/api/merge_requests/#get-single-mr-diffs
        该API在Gitlab 11.5 引入（GPT），在查询了14.10版本的API文档后，可以确定是该版本没有diffs接口导致的
        """
        # 检查是否为 Merge Request Hook 事件
        if self.event_type != 'merge_request':
            logger.warn(f"Invalid event type: {self.event_type}. Only 'merge_request' event is supported now.")
            return []

        # Gitlab merge request diffs API可能存在延迟，多次尝试
        max_retries = 3  # 最大重试次数
        retry_delay = 10  # 重试间隔时间（秒）
        for attempt in range(max_retries):
            # 调用 GitLab API 获取 Merge Request 的 diffs
            url = urljoin(f"{self.gitlab_url}/",
                          f"api/v4/projects/{self.project_id}/merge_requests/{self.merge_request_iid}/diffs")
            headers = {
                'PRIVATE-TOKEN': self.gitlab_token
            }
            response = requests.get(url, headers=headers, verify=False)
            logger.debug(
                f"Get diffs response from GitLab (attempt {attempt + 1}): {response.status_code}, {response.text}, URL: {url}")
            # 检查请求是否成功
            if response.status_code == 200:
                diffs = response.json()
                if diffs:
                    return diffs
                else:
                    logger.info(
                        f"diffs is empty, retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries}), URL: {url}")
                    time.sleep(retry_delay)
            else:
                logger.warn(f"Failed to get diffs from GitLab (URL: {url}): {response.status_code}, {response.text}")
                return []

        logger.warning(f"Max retries ({max_retries}) reached. diffs is still empty.")
        return []  # 达到最大重试次数后返回空列表

    def get_merge_request_diffs_from_base_sha_to_head_sha(self) -> list:
        """
        原方法: get_merge_request_changes，由于diffs接口当前项目有问题，所以使用了替代方案
        注意：该方案的性能待验证，评审阶段提出该接口存在性能问题，响应慢等
        API: GET /projects/:id/merge_requests/:merge_request_iid/diffs
        API URL: https://docs.gitlab.com/api/merge_requests/#get-single-mr-diffs
        当前项目不支持diffs接口

        该方法暂时不使用了，还是使用changes接口...
        """
        max_retries = 3  # 最大重试次数
        retry_delay = 10  # 重试间隔时间（秒）
        headers = {
            'PRIVATE-TOKEN': self.gitlab_token
        }
        sha = self.get_merge_request_sha()
        # 根据获取的 mr 信息，通过 sha 获取完整的 diffs 内容
        for attempt in range(max_retries):
            # 调用 GitLab API 获取 Merge Request 的 diffs
            url = urljoin(f"{self.gitlab_url}/",
                          f"api/v4/projects/{self.project_id}/repository/compare?from={sha['base_sha']}&to={sha['head_sha']}")
            response = requests.get(url, headers=headers, verify=False)
            logger.debug(
                f"Get diffs response from GitLab (attempt {attempt + 1}): {response.status_code}, {response.text}, URL: {url}")

            # 检查请求是否成功
            if response.status_code == 200:
                diffs = response.json().get('diffs', [])
                if diffs:
                    return diffs
                else:
                    logger.info(
                        f"diffs is empty, retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries}), URL: {url}")
                    time.sleep(retry_delay)
            else:
                logger.warn(f"Failed to get diffs from GitLab (URL: {url}): {response.status_code}, {response.text}")
                return []

        logger.warning(f"Max retries ({max_retries}) reached. diffs is still empty.")
        return []  # 达到最大重试次数后返回空列表


    def get_merge_request_commits(self) -> list:
        # 检查是否为 Merge Request Hook 事件
        if self.event_type != 'merge_request':
            return []

        # 调用 GitLab API 获取 Merge Request 的 commits
        url = urljoin(f"{self.gitlab_url}/",
                      f"api/v4/projects/{self.project_id}/merge_requests/{self.merge_request_iid}/commits")
        headers = {
            'Private-Token': self.gitlab_token
        }
        response = requests.get(url, headers=headers, verify=False)
        logger.debug(f"Get commits response from gitlab: {response.status_code}, {response.text}")
        # 检查请求是否成功
        if response.status_code == 200:
            return response.json()
        else:
            logger.warn(f"Failed to get commits: {response.status_code}, {response.text}")
            return []

    def add_merge_request_notes(self, review_result):
        url = urljoin(f"{self.gitlab_url}/",
                      f"api/v4/projects/{self.project_id}/merge_requests/{self.merge_request_iid}/notes")
        headers = {
            'Private-Token': self.gitlab_token,
            'Content-Type': 'application/json'
        }
        data = {
            'body': review_result
        }
        response = requests.post(url, headers=headers, json=data, verify=False)
        logger.debug(f"Add notes to gitlab {url}: {response.status_code}, {response.text}")
        if response.status_code == 201:
            logger.info("Note successfully added to merge request.")
        else:
            logger.error(f"Failed to add note: {response.status_code}")
            logger.error(response.text)

    def add_merge_request_discussions_on_row(
        self,
        content, 
        base_sha, 
        head_sha, 
        start_sha, 
        old_path, 
        new_path, 
        old_line=None, 
        new_line=None
    ):
        """
        对MR的指定行添加评论discussions

        【代办】如果行号为空，或者行内评论添加失败，就使用原本的方式添加到末尾
        """

        # gitlab api 文档路径
        # API: POST /projects/:id/merge_requests/:merge_request_iid/discussions
        # Latest URL: https://docs.gitlab.com/api/discussions/#create-a-new-thread-in-the-merge-request-diff
        # Local URL: :4000/14.10/ee/api/discussions.html#create-new-merge-request-thread

        # 获取GitLab Token（优先级：请求头 > 环境变量 ）
        private_token = request.headers.get('X-Gitlab-Token') or os.getenv('GITLAB_ACCESS_TOKEN')
        if not private_token:
            # 可以根据实际场景选择返回None、空字符串或其他合适的值
            logger.error("Get GITLAB_ACCESS_TOKEN is None, please check env.")
            return None
        
        url = f"{self.gitlab_url}/api/v4/projects/{self.project_id}/merge_requests/{self.merge_request_iid}/discussions"
        
        headers = {
            "Private-Token": private_token,
            "Content-Type": "application/json"
        }
        
        payload = {
            "body": content,
            "position": {
                "base_sha": base_sha,
                "head_sha": head_sha,
                "start_sha": start_sha,
                "old_path": old_path,
                "new_path": new_path,
                "position_type": "text"  # 必须指定为 text（文本文件）
            }
        }
        
        if old_line is not None:
            payload["position"]["old_line"] = old_line
        if new_line is not None:
            payload["position"]["new_line"] = new_line
        
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        
        if response.status_code == 201:
            logger.info(f"向文件{new_path}的{old_line}~{new_line}行添加评论成功")
            return response.json()
        else:
            logger.error(f"向文件{new_path}的{old_line}~{new_line}行添加评论失败。状态码: {response.status_code}")
            logger.error(f"请求信息：\n url: {url}\n header: Just Private-Token, dont print\n position: {payload['position']}")
            logger.error(f"响应内容: {response.text}")
            logger.warn("由于行内评论添加失败，使用原本的方式直接向MR提交评论")
            self.add_merge_request_notes(f"注意：本次行内评论由于异常原因未添加成功，请根据AICR查看对应的行：\n{content}")
            return None

    def target_branch_protected(self) -> bool:
        url = urljoin(f"{self.gitlab_url}/",
                      f"api/v4/projects/{self.project_id}/protected_branches")
        headers = {
            'Private-Token': self.gitlab_token,
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers, verify=False)
        logger.debug(f"Get protected branches response from gitlab: {response.status_code}, {response.text}")
        # 检查请求是否成功
        if response.status_code == 200:
            data = response.json()
            target_branch = self.webhook_data['object_attributes']['target_branch']
            return any(fnmatch.fnmatch(target_branch, item['name']) for item in data)
        else:
            logger.warn(f"Failed to get protected branches: {response.status_code}, {response.text}")
            return False

    def get_gitlab_file_content(
        self,
        file_path: str,
        branch_type: str,  # 分支名、标签或commit SHA
        ref: str = None,
    ) -> Optional[str]:
        """
        通过GitLab API获取指定项目、分支下文件的完整内容
        
        Args:
            gitlab_url: GitLab实例地址（如https://gitlab.com）
            project_id: 项目ID（数字ID，非路径）
            file_path: 文件在仓库中的相对路径
            ref: 分支名、标签或commit SHA
            branch_type: branch_type 和 ref 必传一个，branch_type优先级更高
                target_branch：获取的 file_content 就是旧的
                source_branch：获取的 file_content 就是新的，就是相较于目标分支修改后的
                file_path：如果file_path在对应的分支上不存在，则会获取失败（比如新增、删除文件的场景）
                如果传了 branch_type (source_branch or target_branch), 就自动获取分支，否则使用 ref 的值
            private_token: GitLab个人访问令牌（需有read_repository、api、read_api权限）
            
        Returns:
            文件内容字符串；获取失败则返回None
        """
        # 获取GitLab Token（优先级：请求头 > 环境变量 ）
        private_token = request.headers.get('X-Gitlab-Token') or os.getenv('GITLAB_ACCESS_TOKEN')
        if not private_token:
            # 可以根据实际场景选择返回None、空字符串或其他合适的值
            logger.error("Get GITLAB_ACCESS_TOKEN is None, please check env.")
            return None
        # GitLab API端点：获取文件内容
        # 文档：https://docs.gitlab.com/ee/api/repository_files.html#get-file-from-repository
        url = f"{self.gitlab_url}/api/v4/projects/{self.project_id}/repository/files/{requests.utils.quote(file_path, safe='')}/raw"
        
        # 如果确定了分支类型，就直接获取
        if branch_type == "source_branch":
            ref = self.source_branch
        elif branch_type == "target_branch":
            ref = self.target_branch

        if ref is None :
            logger.error("未获取到需要文件所在分支信息")
            return None
        params = {
            "ref": ref
        }
        
        headers = {
            "Private-Token": private_token
        }
        
        try:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()  # 触发HTTP错误状态码的异常
            logger.debug(f"从{ref}获取{file_path}文件内容成功")
            logger.debug(f"文件内容为：\n{response.text}")
            return response.text
        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                logger.warning(f"文件 {file_path} 在分支 {ref} 中不存在: {str(e)}")
            else:
                logger.error(f"API请求失败 (状态码: {response.status_code}): {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取文件内容时发生异常: {str(e)}")
            return None

class PushHandler:
    def __init__(self, webhook_data: dict, gitlab_token: str, gitlab_url: str):
        self.webhook_data = webhook_data
        self.gitlab_token = gitlab_token
        self.gitlab_url = gitlab_url
        self.event_type = None
        self.project_id = None
        self.branch_name = None
        self.commit_list = []
        self.parse_event_type()

    def parse_event_type(self):
        # 提取 event_type
        self.event_type = self.webhook_data.get('event_name', None)
        if self.event_type == 'push':
            self.parse_push_event()

    def parse_push_event(self):
        # 提取 Push 事件的相关参数
        self.project_id = self.webhook_data.get('project', {}).get('id')
        self.branch_name = self.webhook_data.get('ref', '').replace('refs/heads/', '')
        self.commit_list = self.webhook_data.get('commits', [])

    def get_push_commits(self) -> list:
        # 检查是否为 Push 事件
        if self.event_type != 'push':
            logger.warn(f"Invalid event type: {self.event_type}. Only 'push' event is supported now.")
            return []

        # 提取提交信息
        commit_details = []
        for commit in self.commit_list:
            commit_info = {
                'message': commit.get('message'),
                'author': commit.get('author', {}).get('name'),
                'timestamp': commit.get('timestamp'),
                'url': commit.get('url'),
            }
            commit_details.append(commit_info)

        logger.info(f"Collected {len(commit_details)} commits from push event.")
        return commit_details

    def add_push_notes(self, message: str):
        # 添加评论到 GitLab Push 请求的提交中（此处假设是在最后一次提交上添加注释）
        if not self.commit_list:
            logger.warn("No commits found to add notes to.")
            return

        # 获取最后一个提交的ID
        last_commit_id = self.commit_list[-1].get('id')
        if not last_commit_id:
            logger.error("Last commit ID not found.")
            return

        url = urljoin(f"{self.gitlab_url}/",
                      f"api/v4/projects/{self.project_id}/repository/commits/{last_commit_id}/comments")
        headers = {
            'Private-Token': self.gitlab_token,
            'Content-Type': 'application/json'
        }
        data = {
            'note': message
        }
        response = requests.post(url, headers=headers, json=data, verify=False)
        logger.debug(f"Add comment to commit {last_commit_id}: {response.status_code}, {response.text}")
        if response.status_code == 201:
            logger.info("Comment successfully added to push commit.")
        else:
            logger.error(f"Failed to add comment: {response.status_code}")
            logger.error(response.text)

    def __repository_commits(self, ref_name: str = "", since: str = "", until: str = "", pre_page: int = 100,
                             page: int = 1):
        # 获取仓库提交信息
        url = f"{urljoin(f'{self.gitlab_url}/', f'api/v4/projects/{self.project_id}/repository/commits')}?ref_name={ref_name}&since={since}&until={until}&per_page={pre_page}&page={page}"
        headers = {
            'Private-Token': self.gitlab_token
        }
        response = requests.get(url, headers=headers, verify=False)
        logger.debug(
            f"Get commits response from GitLab for repository_commits: {response.status_code}, {response.text}, URL: {url}")

        if response.status_code == 200:
            return response.json()
        else:
            logger.warn(
                f"Failed to get commits for ref {ref_name}: {response.status_code}, {response.text}")
            return []

    def get_parent_commit_id(self, commit_id: str) -> str:
        commits = self.__repository_commits(ref_name=commit_id, pre_page=1, page=1)
        if commits and commits[0].get('parent_ids', []):
            return commits[0].get('parent_ids', [])[0]
        return ""

    def repository_compare(self, before: str, after: str):
        # 比较两个提交之间的差异
        url = f"{urljoin(f'{self.gitlab_url}/', f'api/v4/projects/{self.project_id}/repository/compare')}?from={before}&to={after}"
        headers = {
            'Private-Token': self.gitlab_token
        }
        response = requests.get(url, headers=headers, verify=False)
        logger.debug(
            f"Get changes response from GitLab for repository_compare: {response.status_code}, {response.text}, URL: {url}")

        if response.status_code == 200:
            return response.json().get('diffs', [])
        else:
            logger.warn(
                f"Failed to get changes for repository_compare: {response.status_code}, {response.text}")
            return []

    def get_push_changes(self) -> list:
        # 检查是否为 Push 事件
        if self.event_type != 'push':
            logger.warn(f"Invalid event type: {self.event_type}. Only 'push' event is supported now.")
            return []

        # 如果没有提交，返回空列表
        if not self.commit_list:
            logger.info("No commits found in push event.")
            return []
        headers = {
            'Private-Token': self.gitlab_token
        }

        # 优先尝试compare API获取变更
        before = self.webhook_data.get('before', '')
        after = self.webhook_data.get('after', '')
        if before and after:
            if after.startswith('0000000'):
                # 删除分支处理
                return []
            if before.startswith('0000000'):
                # 创建分支处理
                first_commit_id = self.commit_list[0].get('id')
                parent_commit_id = self.get_parent_commit_id(first_commit_id)
                if parent_commit_id:
                    before = parent_commit_id
            return self.repository_compare(before, after)
        else:
            return []
