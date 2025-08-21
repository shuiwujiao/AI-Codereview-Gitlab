# AI代码审查项目 - 大模型关键词配置说明

## 项目概述

这是一个基于大模型的自动化代码审查工具，支持多种大模型供应商，通过Webhook机制对GitLab/GitHub的代码提交进行智能审查。

## 核心关键词配置

### 1. 大模型供应商配置

**位置**: `biz/llm/factory.py`

项目支持多种大模型供应商，通过 `LLM_PROVIDER` 环境变量配置：

```python
# 支持的大模型供应商
chat_model_providers = {
    'zhipuai': lambda: ZhipuAIClient(),      # 智谱AI
    'openai': lambda: OpenAIClient(),        # OpenAI
    'deepseek': lambda: DeepSeekClient(),    # DeepSeek
    'qwen': lambda: QwenClient(),           # 通义千问
    'ollama': lambda : OllamaClient()       # Ollama
}
```

### 2. 各模型API配置

**位置**: `biz/llm/client/` 目录下的各客户端文件

每个模型都有对应的API配置环境变量：

| 模型 | API密钥 | API地址 | 模型名称 |
|------|---------|---------|----------|
| **OpenAI** | `OPENAI_API_KEY` | `OPENAI_API_BASE_URL` | `OPENAI_API_MODEL` |
| **DeepSeek** | `DEEPSEEK_API_KEY` | `DEEPSEEK_API_BASE_URL` | `DEEPSEEK_API_MODEL` |
| **智谱AI** | `ZHIPUAI_API_KEY` | - | `ZHIPUAI_API_MODEL` |
| **通义千问** | `QWEN_API_KEY` | `QWEN_API_BASE_URL` | `QWEN_API_MODEL` |
| **Ollama** | - | `OLLAMA_API_BASE_URL` | `OLLAMA_API_MODEL` |

### 3. 代码审查提示词模板

**位置**: `conf/prompt_templates.yml`

这是项目的核心关键词配置，定义了代码审查的标准化提示词：

```yaml
code_review_prompt:
  system_prompt: |-
    你是一位资深的软件开发工程师，专注于代码的规范性、功能性、安全性和稳定性。
    
    ### 代码审查目标：
    1. 功能实现的正确性与健壮性（40分）：确保代码逻辑正确，能够处理各种边界情况和异常输入
    2. 安全性与潜在风险（30分）：检查代码是否存在安全漏洞，并评估其潜在风险
    3. 是否符合最佳实践（20分）：评估代码是否遵循行业最佳实践
    4. 性能与资源利用效率（5分）：分析代码的性能表现
    5. Commits信息的清晰性与准确性（5分）：检查提交信息是否清晰、准确
```

### 4. 审查风格配置

**位置**: `biz/utils/code_reviewer.py`

通过 `REVIEW_STYLE` 环境变量控制审查风格：

- **`professional`**: 专业严谨风格 - 使用标准的工程术语，保持专业严谨
- **`sarcastic`**: 讽刺性语言风格 - 大胆使用讽刺性语言，但要确保技术指正准确
- **`gentle`**: 温和建议风格 - 多用"建议"、"可以考虑"等温和措辞
- **`humorous`**: 幽默风格 - 在技术点评中加入适当幽默元素和Emoji

### 5. 文件类型过滤配置

**位置**: `biz/gitlab/webhook_handler.py`, `biz/github/webhook_handler.py`

通过 `SUPPORTED_EXTENSIONS` 环境变量控制哪些文件类型会被审查：

```bash
SUPPORTED_EXTENSIONS=.java,.py,.php,.yml,.vue,.go,.c,.cpp,.h,.js,.css,.md,.sql
```

### 6. Token限制配置

**位置**: `biz/utils/code_reviewer.py`

通过 `REVIEW_MAX_TOKENS` 环境变量控制发送给大模型的文本长度：

```python
review_max_tokens = int(os.getenv("REVIEW_MAX_TOKENS", 10000))
```

### 7. 功能开关配置

- **`PUSH_REVIEW_ENABLED`**: 是否启用Push事件审查
- **`MERGE_REVIEW_ONLY_PROTECTED_BRANCHES_ENABLED`**: 是否仅对受保护分支进行审查

### 8. 详细审查模式配置（新增）

**位置**: `conf/prompt_templates.yml`, `biz/utils/code_reviewer.py`

通过以下配置实现更细致的代码审查：

#### 8.1 智能语言检测
系统会自动检测代码的主要编程语言，并选择相应的专业审查提示词：

- **Python代码**: 使用 `python_review_prompt`，重点关注PEP 8规范、类型提示、异常处理等
- **JavaScript/TypeScript代码**: 使用 `javascript_review_prompt`，重点关注ES6+特性、类型安全、异步处理等
- **Vue3代码**: 使用 `vue3_review_prompt`，重点关注Composition API、性能优化、TypeScript集成等
- **Java代码**: 使用 `java_review_prompt`，重点关注设计模式、异常处理、线程安全等
- **其他语言**: 使用通用 `code_review_prompt`

#### 8.2 Vue3专门审查功能

**Vue3检测机制**：
- 自动识别Vue文件（.vue扩展名）
- 检测Vue3特有语法特征（setup()、defineProps、ref()、reactive()等）
- 智能选择Vue3专用审查提示词

**Vue3审查维度**：
1. **Composition API使用**：
   - 响应式数据：ref()、reactive()、computed()的正确使用
   - 生命周期钩子：onMounted()、onUnmounted()等
   - 组合函数：composables的最佳实践
   - 响应式解构：避免响应性丢失

2. **模板语法和指令**：
   - v-if vs v-show的正确选择
   - v-for优化：key属性使用、避免v-if/v-for混用
   - 事件处理：@click等指令的正确使用
   - 双向绑定：v-model的自定义和优化

3. **组件设计**：
   - Props定义：TypeScript类型、默认值设置
   - Emits定义：事件类型定义和验证
   - 组件通信：props/emits、provide/inject、Pinia使用
   - 组件拆分：职责单一、避免过度复杂

4. **性能优化**：
   - 响应式优化：避免不必要的响应式数据
   - 计算属性：computed()缓存计算结果
   - 异步组件：defineAsyncComponent代码分割
   - 虚拟滚动：大数据列表优化

5. **TypeScript集成**：
   - 类型定义：组件props、emits、refs的类型
   - 泛型使用：提高类型安全性
   - 接口定义：清晰的类型接口

6. **状态管理**：
   - Pinia使用：正确的状态管理方式
   - 状态设计：合理的状态结构
   - 持久化：状态持久化实现

7. **路由和导航**：
   - 路由守卫：权限控制实现
   - 路由懒加载：性能优化
   - 路由参数：参数处理最佳实践

8. **错误处理和调试**：
   - 错误边界：组件错误处理
   - 调试工具：Vue DevTools使用
   - 错误日志：错误记录和上报

9. **样式和UI**：
   - CSS作用域：scoped样式使用
   - CSS变量：主题切换实现
   - 响应式设计：移动端适配

10. **测试和文档**：
    - 单元测试：组件测试编写
    - 文档注释：JSDoc注释
    - README：组件使用说明

**Vue3代码示例对比**：
- 提供修改前后的完整代码对比
- 详细的修改说明和好处解释
- 引用Vue3官方文档和最佳实践
- 包含性能优化建议和代码规范建议

#### 8.2 详细审查维度
每个审查都会从以下维度进行详细分析：

**代码质量检查**:
- 命名规范：变量、函数、类名是否清晰、有意义、符合语言规范
- 代码结构：函数长度、复杂度、嵌套层级是否合理
- 注释质量：是否有必要的注释，注释是否准确、有用
- 代码重复：是否存在重复代码，是否可以通过重构优化

**安全性检查**:
- 输入验证：是否正确验证和清理用户输入
- SQL注入防护：是否使用参数化查询或ORM
- XSS防护：是否正确转义输出内容
- 权限控制：是否正确检查用户权限
- 敏感信息：是否暴露了敏感信息（密码、密钥等）

**性能优化**:
- 算法效率：是否存在性能瓶颈，时间复杂度是否合理
- 资源管理：是否正确管理内存、数据库连接等资源
- 缓存使用：是否合理使用缓存机制
- 数据库查询：查询是否优化，是否避免N+1问题

**错误处理**:
- 异常处理：是否正确处理异常情况
- 边界条件：是否考虑了各种边界情况
- 错误信息：错误信息是否清晰、有用
- 日志记录：是否记录了必要的日志信息

**可维护性**:
- 模块化：代码是否模块化，职责是否清晰
- 可测试性：代码是否易于测试
- 可扩展性：代码是否易于扩展和修改
- 文档完整性：是否有必要的文档说明

#### 8.3 输出格式要求
审查报告会包含以下详细内容：

1. **问题描述和优化建议**:
   - 问题位置：明确指出问题所在的文件、行号
   - 问题描述：详细描述问题是什么
   - 影响分析：说明这个问题可能带来的影响
   - 具体建议：提供具体的修改建议，包括代码示例
   - 优先级：标注问题的严重程度（高/中/低）

2. **代码示例**:
   - 修改前代码：展示当前有问题的代码
   - 修改后代码：展示优化后的代码
   - 修改说明：解释为什么要这样修改

3. **评分明细**:
   - 具体分数：给出详细分数
   - 扣分原因：说明扣分的具体原因
   - 改进建议：针对该维度的改进建议

4. **总结**:
   - 主要问题：总结发现的主要问题
   - 改进重点：指出最需要优先改进的方面
   - 总分：格式为"总分:XX分"

## 专项审查提示词

### 1. 目录结构审查

**位置**: `biz/cmd/func/directory.py`

```python
SYSTEM_PROMPT = """
你是一位资深的软件架构师，本次任务是对一个代码库进行审查，具体要求如下：
### 具体要求：
1. 组织逻辑：评估目录结构是否清晰，是否符合常见的项目组织规范
2. 命名规范性：检查目录和文件的命名是否清晰、一致
3. 模块化程度：评估代码是否按功能或模块合理划分
4. 可维护性：分析目录结构是否易于扩展和维护
5. 改进建议：针对发现的问题，提出具体的优化建议
"""
```

### 2. MySQL数据库审查

**位置**: `biz/cmd/func/mysql.py`

```python
SYSTEM_PROMPT = """
你是一个经验丰富的数据库架构专家，擅长MySQL数据库设计评审和性能优化。你在评审数据库结构时会从以下角度进行系统性的分析并提出可操作的建议：
1. 表结构设计（命名规范、主键设置、字段设计等）
2. 字段类型是否合理（如金额使用DECIMAL、避免TEXT/BLOB滥用等）
3. 索引设计（是否有必要索引、冗余索引、联合索引顺序等）
4. 表与表之间的关系建模（是否正确使用外键、中间表、多对多等）
5. 性能与容量规划（是否考虑数据量增长、归档、冷热数据等）
6. 安全性（是否有敏感数据加密、访问控制）
7. 可维护性与扩展性（命名规范、注释、迁移工具支持等）
"""
```

### 3. 分支审查

**位置**: `biz/cmd/func/branch.py`

```python
SYSTEM_PROMPT = """
你是一位资深的Git分支管理专家，本次任务是对Git分支策略进行审查，具体要求如下：
### 具体要求：
1. 分支命名规范：检查分支命名是否符合团队约定
2. 分支策略合理性：评估当前分支策略是否适合项目规模
3. 合并策略：分析合并策略是否合理，是否存在潜在冲突
4. 分支生命周期：评估分支的创建、使用、合并、删除流程
5. 改进建议：针对发现的问题，提出具体的优化建议
"""
```

## 配置检查机制

**位置**: `biz/utils/config_checker.py`

项目包含完整的配置检查机制，确保必要的环境变量都已正确设置：

```python
def check_llm_provider():
    """检查LLM供应商配置"""
    llm_provider = os.getenv("LLM_PROVIDER")
    if not llm_provider:
        logger.error("LLM_PROVIDER 未设置！")
        return False
    
    if llm_provider not in LLM_PROVIDERS:
        logger.error(f"LLM_PROVIDER 值错误，应为 {LLM_PROVIDERS} 之一。")
        return False
    
    # 检查对应供应商的必要环境变量
    required_keys = LLM_REQUIRED_KEYS.get(llm_provider, [])
    missing_keys = [key for key in required_keys if not os.getenv(key)]
    
    if missing_keys:
        logger.error(f"当前 LLM 供应商为 {llm_provider}，但缺少必要的环境变量: {', '.join(missing_keys)}")
        return False
    
    logger.info(f"LLM 供应商 {llm_provider} 的配置项已设置。")
    return True
```

## 环境变量配置示例

```bash
# 大模型供应商配置
LLM_PROVIDER=deepseek

# DeepSeek配置
DEEPSEEK_API_KEY=your_api_key_here
DEEPSEEK_API_BASE_URL=https://api.deepseek.com
DEEPSEEK_API_MODEL=deepseek-chat

# 审查配置
REVIEW_STYLE=professional
REVIEW_MAX_TOKENS=10000
SUPPORTED_EXTENSIONS=.java,.py,.php,.yml,.vue,.go,.c,.cpp,.h,.js,.css,.md,.sql

# 功能开关
PUSH_REVIEW_ENABLED=1
MERGE_REVIEW_ONLY_PROTECTED_BRANCHES_ENABLED=0

# GitLab配置
GITLAB_ACCESS_TOKEN=your_gitlab_token_here
GITLAB_URL=https://your-gitlab-instance.com

# 消息推送配置
DINGTALK_ENABLED=1
DINGTALK_WEBHOOK_URL=your_dingtalk_webhook_url
```

## 总结

这个项目的大模型关键词配置具有以下特点：

1. **多模型供应商支持** - 通过环境变量灵活切换不同的大模型
2. **标准化的代码审查提示词** - 统一的审查标准和评分体系
3. **多样化的审查风格** - 适应不同的团队文化和工作氛围
4. **专业化的专项审查** - 针对目录结构、数据库等特定场景的专用提示词
5. **智能语言检测** - 自动识别代码语言并使用相应的专业审查提示词
6. **详细的审查维度** - 从代码质量、安全性、性能、错误处理、可维护性等多个维度进行深入分析
7. **完善的配置检查** - 确保系统配置的正确性和完整性

所有的关键词配置都通过环境变量或配置文件进行管理，使得系统具有很好的灵活性和可配置性，能够适应不同团队的需求。通过新增的详细审查模式，系统能够提供更加专业和细致的代码审查建议。