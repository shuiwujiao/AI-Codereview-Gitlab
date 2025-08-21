import os
from typing import Dict, List, Optional, Union

from biz.llm.client.base import BaseClient
from biz.llm.types import NotGiven, NOT_GIVEN
from biz.utils.log import logger
import zhipuai


class ZhipuAIClient(BaseClient):
    """Zhipuai client for chat models."""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ZHIPUAI_API_KEY")
        if not self.api_key:
            raise ValueError("API key is required. Please provide it or set it in the environment variables.")
        self.client = zhipuai.ZhipuAI(api_key=self.api_key)
        self.default_model = os.getenv("ZHIPUAI_API_MODEL", "glm-4")

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
