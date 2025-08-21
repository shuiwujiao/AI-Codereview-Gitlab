import os
from typing import Dict, List, Optional, Union
from transformers import AutoTokenizer, PreTrainedTokenizer
import tiktoken

from openai import OpenAI

from biz.llm.client.base import BaseClient
from biz.llm.types import NotGiven, NOT_GIVEN
from biz.utils.log import logger
import openai

class QwenClient(BaseClient):
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("QWEN_API_KEY")
        self.base_url = os.getenv("QWEN_API_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        if not self.api_key:
            raise ValueError("API key is required. Please provide it or set it in the environment variables.")

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        self.default_model = os.getenv("QWEN_API_MODEL", "qwen-coder-plus")
        self.extra_body={"enable_thinking": False}

    def completions(self,
                    messages: List[Dict[str, str]],
                    model: Union[Optional[str], NotGiven] = NOT_GIVEN,
                    ) -> str:
        model = model or self.default_model
        completion = self.client.chat.completions.create(
            model=model,
            messages=messages,
            extra_body=self.extra_body,
        )
        return completion.choices[0].message.content

class EnhancedQwenClient(QwenClient):
    """增强版OpenAI客户端：继承基础类，新增temperature/top_p等参数配置能力，主要是适配qwen"""

    def __init__(self, api_key: str = None):
        # 1. 调用父类（原基础类）的构造函数，保留原有的API密钥、BaseURL、客户端初始化逻辑
        super().__init__(api_key=api_key)
        
        # 2. 在父类基础上，新增默认参数的初始化（从环境变量读取，或用默认值）
        self.default_temperature = float(os.getenv("QWEN_API_DEFAULT_TEMPERATURE", 0.6))
        self.default_top_p = float(os.getenv("QWEN_API_DEFAULT_TOP_P", 0.95))
        self.default_top_k = int(os.getenv("QWEN_API_DEFAULT_TOP_K", 20))
        self.default_max_tokens = int(os.getenv("QWEN_API_DEFAULT_MAX_TOKENS", 15000))

    def count_tokens(self, text: str, model: Union[Optional[str], NotGiven] = NOT_GIVEN) -> int:
        """
        计算文本的token数量，根据模型自动选择计算方式
        
        Args:
            text: 需要计算token的文本
            model: 模型名称，默认使用类的默认模型
            
        Returns:
            文本的token数量
        备注：
            没有单独适配qwen模型, 未调通, gpt和qwen计算出来的token数为gpt多于qwen 10%左右
        """
        used_model = model if model is not NOT_GIVEN else self.default_model
        
        if not text:
            return 0
            
        try:
            # 获取指定模型的编码方式
            encoding = tiktoken.encoding_for_model(used_model)
            # 计算token数量
            return len(encoding.encode(text))
        except KeyError:
            # 未找到模型时，使用默认编码方式
            encoding = tiktoken.get_encoding("cl100k_base")
            return len(encoding.encode(text))

    def completions(self,
                    messages: List[Dict[str, str]],
                    model: Union[Optional[str], NotGiven] = NOT_GIVEN,
                    # 3. 新增参数，与父类方法兼容
                    temperature: Union[Optional[float], NotGiven] = NOT_GIVEN,
                    top_p: Union[Optional[float], NotGiven] = NOT_GIVEN,
                    top_k: Union[Optional[int], NotGiven] = NOT_GIVEN,
                    max_tokens: Union[Optional[int], NotGiven] = NOT_GIVEN,
                    ) -> str:
        # 4. 优先使用调用时传入的参数，否则使用类的默认值（兼容父类的model逻辑）
        used_model = model if model is not NOT_GIVEN else self.default_model
        used_temperature = temperature if temperature is not NOT_GIVEN else self.default_temperature
        used_top_p = top_p if top_p is not NOT_GIVEN else self.default_top_p
        used_top_k = top_k if top_k is not NOT_GIVEN else self.default_top_k
        used_max_tokens = max_tokens if max_tokens is not NOT_GIVEN else self.default_max_tokens

        # 5. 计算实际允许的 max_tokens = default_max_tokens - tokens(message)
        input_tokens = self.count_tokens(text=str(messages))
        if input_tokens >= used_max_tokens:
            return f"本次review token为: {input_tokens}, 超过最大值：{used_max_tokens}, 暂不处理"
        used_max_tokens = used_max_tokens - input_tokens

        # 6. 调用OpenAI API时传入所有参数
        completion = self.client.chat.completions.create(
            model=used_model,
            messages=messages,
            temperature=used_temperature,
            top_p=used_top_p,
            max_tokens=used_max_tokens,
            extra_body={
                "top_k": used_top_k,
            },
        )
        return completion.choices[0].message.content