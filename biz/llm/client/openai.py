import os
from typing import Dict, List, Optional, Union

from openai import OpenAI
import tiktoken

from biz.llm.client.base import BaseClient
from biz.llm.types import NotGiven, NOT_GIVEN


class OpenAIClient(BaseClient):
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = os.getenv("OPENAI_API_BASE_URL", "https://api.openai.com")
        if not self.api_key:
            raise ValueError("API key is required. Please provide it or set it in the environment variables.")

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        self.default_model = os.getenv("OPENAI_API_MODEL", "gpt-4o-mini")

    def completions(self,
                    messages: List[Dict[str, str]],
                    model: Union[Optional[str], NotGiven] = NOT_GIVEN,
                    ) -> str:
        model = model or self.default_model
        completion = self.client.chat.completions.create(
            model=model,
            messages=messages,
        )
        return completion.choices[0].message.content

    def count_tokens(self, text: str, model: Union[Optional[str], NotGiven] = NOT_GIVEN) -> int:
        """
        计算文本的token数量，根据模型自动选择计算方式
        
        Args:
            text: 需要计算token的文本
            model: 模型名称，默认使用类的默认模型
            
        Returns:
            文本的token数量
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
