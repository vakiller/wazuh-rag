"""
LLM Client Module

Handles communication with Ollama LLM via LangChain
"""

import logging
import json
import re
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Client for interacting with local Ollama LLM via LangChain
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        temperature: float = 0.1,
        timeout: int = 120,
        max_retries: int = 3
    ):
        """
        Initialize LLM client

        Args:
            base_url: Ollama API endpoint (e.g., http://192.168.1.11:11434)
            model: Model name (e.g., llama3.1:8b-instruct-q4_K_M)
            temperature: Sampling temperature (0.0 = deterministic)
            timeout: Request timeout in seconds
            max_retries: Number of retries on failure
        """
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.llm = None

        logger.info(f"Initializing LLM client: {model} at {base_url}")
        self._init_llm()

    def _init_llm(self):
        """Initialize LangChain Ollama client"""
        try:
            from langchain_ollama import OllamaLLM
        except ImportError:
            # Fallback to old import for backward compatibility
            try:
                from langchain_community.llms import Ollama as OllamaLLM
                logger.warning(
                    "Using deprecated langchain-community. "
                    "Consider upgrading: pip install -U langchain-ollama"
                )
            except ImportError:
                raise ImportError(
                    "langchain-ollama not installed. "
                    "Install with: pip install langchain-ollama"
                )

        try:
            self.llm = OllamaLLM(
                base_url=self.base_url,
                model=self.model,
                temperature=self.temperature,
                timeout=self.timeout
            )
            logger.info("LLM client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            raise

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> Dict[str, Any]:
        """
        Send analysis request to LLM and parse structured response

        Args:
            system_prompt: System instructions
            user_prompt: User query with evidence

        Returns:
            Parsed JSON response from LLM

        Raises:
            Exception: If LLM call fails or response cannot be parsed
        """
        # Combine prompts
        full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"

        logger.info(f"Sending analysis request to LLM (prompt length: {len(full_prompt)} chars)")

        # Try multiple times in case of transient errors
        for attempt in range(1, self.max_retries + 1):
            try:
                # Call LLM
                response = self.llm.invoke(full_prompt)

                logger.debug(f"Raw LLM response: {response[:500]}...")

                # Parse JSON response
                parsed = self._parse_json_response(response)

                if parsed:
                    logger.info("Successfully parsed LLM response")
                    return parsed
                else:
                    logger.warning(f"Failed to parse JSON (attempt {attempt}/{self.max_retries})")

                    if attempt < self.max_retries:
                        # Try to fix common JSON errors and retry
                        continue

            except Exception as e:
                logger.error(f"LLM call failed (attempt {attempt}/{self.max_retries}): {e}")

                if attempt >= self.max_retries:
                    raise

        # If all retries failed, return fallback structure
        logger.error("All retry attempts exhausted, returning fallback response")
        return self._get_fallback_response()

    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """
        Extract and parse JSON from LLM response

        Handles various formats:
        - Pure JSON
        - JSON wrapped in markdown code blocks
        - JSON with additional text before/after
        - DeepSeek-R1 <think>...</think> and <answer>...</answer> tags

        Args:
            response: Raw LLM response

        Returns:
            Parsed JSON dict or None if parsing fails
        """
        # DeepSeek-R1 specific: Extract from <answer> tags if present
        answer_match = re.search(r'<answer>\s*(.*?)\s*</answer>', response, re.DOTALL | re.IGNORECASE)
        if answer_match:
            response = answer_match.group(1)
            logger.debug("Extracted content from DeepSeek-R1 <answer> tags")

        # Try direct JSON parse first
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from markdown code block
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to find JSON object in text (greedy match for complete object)
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        # Try to fix common JSON errors
        try:
            # Remove trailing commas
            fixed = re.sub(r',(\s*[}\]])', r'\1', response)
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

        logger.error("Could not extract valid JSON from LLM response")
        return None

    def _get_fallback_response(self) -> Dict[str, Any]:
        """
        Generate fallback response when LLM fails

        Returns:
            Minimal valid response structure
        """
        return {
            'summary': 'LLM analysis failed - manual review required',
            'mitre_list': [],
            'predictions': [
                {
                    'action': 'LLM analysis unavailable',
                    'confidence': 'Low',
                    'reasoning': 'System error prevented automated analysis'
                }
            ],
            'suggested_actions': [
                {
                    'step': 1,
                    'action': 'Review raw alerts manually',
                    'priority': 'High'
                },
                {
                    'step': 2,
                    'action': 'Check LLM service availability',
                    'priority': 'Medium'
                }
            ],
            'evidence_map': [],
            'iocs': {
                'ips': [],
                'hashes': [],
                'domains': [],
                'file_paths': [],
                'accounts': [],
                'processes': []
            },
            'confidence_overall': 0,
            'tldr': 'Automated analysis failed',
            'error': 'LLM service unavailable or response parsing failed'
        }

    def test_connection(self) -> bool:
        """
        Test connection to Ollama API

        Returns:
            True if connection successful, False otherwise
        """
        try:
            test_prompt = "Respond with only the word 'OK' if you can read this."
            response = self.llm.invoke(test_prompt)

            if response and len(response) > 0:
                logger.info(f"LLM connection test successful: {response[:100]}")
                return True
            else:
                logger.warning("LLM responded but with empty content")
                return False

        except Exception as e:
            logger.error(f"LLM connection test failed: {e}")
            return False

    def __repr__(self) -> str:
        return f"LLMClient(model={self.model}, url={self.base_url})"
