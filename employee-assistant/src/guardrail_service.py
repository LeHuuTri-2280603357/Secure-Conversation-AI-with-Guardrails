import boto3
import os
from dotenv import load_dotenv
import json
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv('config/.env')

class GuardrailService:
    """
    Service để kiểm tra nội dung với AWS Bedrock Guardrail
    
    Hỗ trợ:
    - Kiểm tra nội dung input
    - Chat với AI có guardrail protection
    - Nhận diện đầy đủ các action: ALLOW, BLOCK, GUARDRAIL_INTERVENED
    """
    
    def __init__(self):
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.guardrail_id = os.getenv('GUARDRAIL_ID')
        self.guardrail_version = os.getenv('GUARDRAIL_VERSION', '1')
        self.model_id = os.getenv('MODEL_ID', 'anthropic.claude-3-haiku-20240307-v1:0')
        
        # Validate configuration
        if not self.guardrail_id:
            raise ValueError(
                "❌ GUARDRAIL_ID không được cấu hình trong file .env\n"
                "Vui lòng thêm: GUARDRAIL_ID=your-guardrail-id"
            )
        
        # Initialize Bedrock client
        try:
            self.bedrock = boto3.client(
                'bedrock-runtime', 
                region_name=self.region
            )
            logger.info(f"✅ Initialized Bedrock client in region: {self.region}")
            logger.info(f"✅ Using Guardrail ID: {self.guardrail_id}")
            logger.info(f"✅ Guardrail Version: {self.guardrail_version}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Bedrock client: {str(e)}")
            raise
    
    def _parse_assessments(self, assessments: list) -> list:
        """
        Parse guardrail assessments để lấy chi tiết vi phạm
        
        Args:
            assessments: List of assessment objects từ guardrail response
            
        Returns:
            List of reason strings
        """
        reasons = []
        
        for assessment in assessments:
            # Content policy violations (Hate, Violence, Sexual, Insults, Misconduct)
            if 'contentPolicy' in assessment:
                filters = assessment['contentPolicy'].get('filters', [])
                for f in filters:
                    action = f.get('action')
                    if action and action != 'NONE':
                        filter_type = f.get('type', 'Unknown')
                        confidence = f.get('confidence', 'N/A')
                        reasons.append(
                            f"Nội dung {filter_type}: {action} (Độ tin cậy: {confidence})"
                        )
            
            # Sensitive information violations (PII)
            if 'sensitiveInformationPolicy' in assessment:
                # PII entities
                pii_entities = assessment['sensitiveInformationPolicy'].get('piiEntities', [])
                for entity in pii_entities:
                    action = entity.get('action')
                    if action and action != 'NONE':
                        entity_type = entity.get('type', 'Unknown')
                        reasons.append(
                            f"Thông tin nhạy cảm ({entity_type}): {action}"
                        )
                
                # Regex matches
                regexes = assessment['sensitiveInformationPolicy'].get('regexes', [])
                for regex in regexes:
                    action = regex.get('action')
                    if action and action != 'NONE':
                        name = regex.get('name', 'Unknown')
                        reasons.append(
                            f"Pattern nhạy cảm ({name}): {action}"
                        )
            
            # Word policy violations
            if 'wordPolicy' in assessment:
                custom_words = assessment['wordPolicy'].get('customWords', [])
                if custom_words:
                    matched = [w.get('match', '') for w in custom_words[:3]]
                    word_list = ', '.join(matched)
                    if len(custom_words) > 3:
                        word_list += '...'
                    reasons.append(
                        f"Từ bị cấm: {word_list}"
                    )
                
                managed_lists = assessment['wordPolicy'].get('managedWordLists', [])
                if managed_lists:
                    reasons.append(
                        f"Managed word list: {len(managed_lists)} vi phạm"
                    )
            
            # Topic policy violations
            if 'topicPolicy' in assessment:
                topics = assessment['topicPolicy'].get('topics', [])
                for topic in topics:
                    action = topic.get('action')
                    if action and action != 'NONE':
                        name = topic.get('name', 'Unknown')
                        reasons.append(
                            f"Chủ đề vi phạm: {name}"
                        )
        
        return reasons
    
    def check_content(self, text: str) -> dict:
        """
        Kiểm tra nội dung với guardrail
        
        Args:
            text: Nội dung cần kiểm tra
            
        Returns:
            Dict với các key:
            - success (bool): Thành công hay không
            - text (str): Nội dung gốc
            - action (str): ALLOW, BLOCK, GUARDRAIL_INTERVENED
            - reasons (list): Lý do vi phạm
            - is_blocked (bool): Có bị chặn không
        """
        try:
            logger.info(f"🔍 Checking content (length: {len(text)}): {text[:100]}...")
            
            # Call guardrail API
            response = self.bedrock.apply_guardrail(
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.guardrail_version,
                content=[{"text": {"text": text}}],
                source="INPUT"
            )
            
            # Extract action and assessments
            action = response.get('action', 'UNKNOWN')
            assessments = response.get('assessments', [])
            outputs = response.get('outputs', [])
            
            logger.info(f"📊 Guardrail action: {action}")
            
            # Parse reasons from assessments
            reasons = self._parse_assessments(assessments)
            
            # Check for masked output
            masked_text = None
            if outputs and len(outputs) > 0:
                masked_text = outputs[0].get('text', '')
                if masked_text != text:
                    logger.info(f"🎭 Content was masked")
            
            # Determine if blocked
            # CRITICAL: GUARDRAIL_INTERVENED means content was blocked!
            is_blocked = action in ['BLOCK', 'GUARDRAIL_INTERVENED']
            
            # Add default reason if blocked but no specific reasons
            if is_blocked and not reasons:
                reasons = ['Nội dung vi phạm chính sách guardrail']
            elif not is_blocked and not reasons:
                reasons = ['Nội dung an toàn']
            
            # Build result
            result = {
                "success": True,
                "text": text,
                "action": action,
                "reasons": reasons,
                "is_blocked": is_blocked
            }
            
            # Add masked text if available
            if masked_text:
                result["masked_text"] = masked_text
            
            # Log result
            if is_blocked:
                logger.warning(f"🚫 Content BLOCKED")
                logger.warning(f"   Reasons: {', '.join(reasons)}")
            else:
                logger.info(f"✅ Content ALLOWED")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error checking content: {str(e)}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
                "text": text,
                "is_blocked": False
            }
    
    def chat_with_ai(self, message: str, system_prompt: str = None) -> dict:
        """
        Chat với AI có guardrail protection
        
        Args:
            message: Tin nhắn của user
            system_prompt: System prompt tùy chọn
            
        Returns:
            Dict với các key:
            - success (bool): Thành công hay không
            - user_message (str): Tin nhắn user
            - ai_response (str): Phản hồi AI
            - is_safe (bool): An toàn hay không
        """
        try:
            logger.info(f"💬 Processing chat message: {message[:100]}...")
            
            # Step 1: Check input với guardrail
            input_check = self.check_content(message)
            
            if input_check.get('is_blocked'):
                logger.warning("⚠️ Input blocked by guardrail")
                return {
                    "success": False,
                    "message": "Tin nhắn của bạn bị chặn vì vi phạm chính sách nội dung",
                    "reasons": input_check.get('reasons', []),
                    "input_check": input_check
                }
            
            # Step 2: Prepare messages
            messages = [
                {
                    "role": "user",
                    "content": [{"text": message}]
                }
            ]
            
            # Step 3: Configure guardrail
            guardrail_config = {
                "guardrailIdentifier": self.guardrail_id,
                "guardrailVersion": self.guardrail_version,
                "trace": "enabled"
            }
            
            # Step 4: Call AI model
            logger.info(f"🤖 Calling model: {self.model_id}")
            
            converse_params = {
                "modelId": self.model_id,
                "messages": messages,
                "inferenceConfig": {
                    "maxTokens": 2000,
                    "temperature": 0.7
                },
                "guardrailConfig": guardrail_config
            }
            
            # Add system prompt if provided
            if system_prompt:
                converse_params["system"] = [{"text": system_prompt}]
            
            response = self.bedrock.converse(**converse_params)
            
            # Step 5: Check stop reason
            stop_reason = response.get('stopReason')
            logger.info(f"🛑 Stop reason: {stop_reason}")
            
            # Check if output was blocked
            if stop_reason == 'guardrail_intervened':
                logger.warning("⚠️ Output blocked by guardrail")
                return {
                    "success": False,
                    "message": "Phản hồi của AI bị chặn vì vi phạm chính sách nội dung",
                    "reasons": ["Output vi phạm guardrail"],
                    "input_check": input_check,
                    "stop_reason": stop_reason
                }
            
            # Step 6: Extract AI response
            ai_response = response['output']['message']['content'][0]['text']
            logger.info(f"✅ AI response generated (length: {len(ai_response)})")
            
            return {
                "success": True,
                "user_message": message,
                "ai_response": ai_response,
                "is_safe": True,
                "input_check": input_check,
                "stop_reason": stop_reason
            }
            
        except Exception as e:
            logger.error(f"❌ Error in chat: {str(e)}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }


# Create global instance
guardrail_service = GuardrailService()


# Example usage / Testing
if __name__ == "__main__":
    print("\n" + "="*70)
    print("🧪 TESTING GUARDRAIL SERVICE")
    print("="*70)
    
    # Test 1: Safe content
    print("\n📝 TEST 1: Safe content")
    print("-" * 70)
    result = guardrail_service.check_content("Xin chào, tôi cần hỗ trợ về sản phẩm")
    print(f"Action: {result['action']}")
    print(f"Blocked: {result['is_blocked']}")
    print(f"Reasons: {result['reasons']}")
    
    # Test 2: Credit card
    print("\n📝 TEST 2: Credit card number")
    print("-" * 70)
    result = guardrail_service.check_content("Số thẻ của tôi là 4111-1111-1111-1111")
    print(f"Action: {result['action']}")
    print(f"Blocked: {result['is_blocked']}")
    print(f"Reasons: {result['reasons']}")
    
    # Test 3: Sexual content
    print("\n📝 TEST 3: Sexual content")
    print("-" * 70)
    result = guardrail_service.check_content("sex")
    print(f"Action: {result['action']}")
    print(f"Blocked: {result['is_blocked']}")
    print(f"Reasons: {result['reasons']}")
    
    # Test 4: Violence
    print("\n📝 TEST 4: Violent content")
    print("-" * 70)
    result = guardrail_service.check_content("I want to kill that person")
    print(f"Action: {result['action']}")
    print(f"Blocked: {result['is_blocked']}")
    print(f"Reasons: {result['reasons']}")
    
    # Test 5: Hate speech
    print("\n📝 TEST 5: Hate speech")
    print("-" * 70)
    result = guardrail_service.check_content("I hate all immigrants")
    print(f"Action: {result['action']}")
    print(f"Blocked: {result['is_blocked']}")
    print(f"Reasons: {result['reasons']}")
    
    # Test 6: Chat with AI
    print("\n📝 TEST 6: Chat with AI")
    print("-" * 70)
    result = guardrail_service.chat_with_ai("Hello, how are you?")
    if result['success']:
        print(f"AI Response: {result['ai_response'][:100]}...")
        print(f"Safe: {result['is_safe']}")
    else:
        print(f"Error: {result.get('message', result.get('error'))}")
    
    print("\n" + "="*70)
    print("✅ TESTING COMPLETE")
    print("="*70)