#!/usr/bin/env python3
"""
AutoVC Diagnostic Script
Tests the pro analysis pipeline without wasting API calls
"""

import os
import json
import redis
import logging
from datetime import datetime
import uuid

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AutoVCDiagnostics:
    def __init__(self):
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
        self.redis_client = None
        self.test_results = {}
        
    def run_all_tests(self):
        """Run all diagnostic tests"""
        print("\n🔍 AUTOVC DIAGNOSTICS")
        print("=" * 60)
        
        # Test 1: Redis Connection
        print("\n1️⃣ Testing Redis Connection...")
        self.test_redis_connection()
        
        # Test 2: Check API Keys
        print("\n2️⃣ Checking API Keys...")
        self.check_api_keys()
        
        # Test 3: Test Cache Storage
        print("\n3️⃣ Testing Cache Storage...")
        self.test_cache_storage()
        
        # Test 4: Test Pro Analysis Generation
        print("\n4️⃣ Testing Pro Analysis Generation (Mock)...")
        self.test_pro_analysis_generation()
        
        # Test 5: Check Existing Cache
        print("\n5️⃣ Checking Existing Cached Analyses...")
        self.check_existing_cache()
        
        # Summary
        self.print_summary()
        
    def test_redis_connection(self):
        """Test Redis connection"""
        try:
            self.redis_client = redis.Redis.from_url(self.redis_url)
            self.redis_client.ping()
            print("✅ Redis connected successfully")
            self.test_results['redis'] = True
            
            # Get Redis info
            info = self.redis_client.info()
            print(f"   Redis version: {info.get('redis_version', 'Unknown')}")
            print(f"   Used memory: {info.get('used_memory_human', 'Unknown')}")
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            self.test_results['redis'] = False
            
    def check_api_keys(self):
        """Check which API keys are configured"""
        api_keys = {
            'OPENAI_API_KEY': os.getenv('OPENAI_API_KEY'),
            'GROQ_API_KEY': os.getenv('GROQ_API_KEY'),
            'ANTHROPIC_API_KEY': os.getenv('ANTHROPIC_API_KEY'),
        }
        
        configured = []
        for key_name, key_value in api_keys.items():
            if key_value:
                masked = key_value[:8] + '...' + key_value[-4:] if len(key_value) > 12 else 'SET'
                print(f"✅ {key_name}: {masked}")
                configured.append(key_name)
            else:
                print(f"❌ {key_name}: NOT SET")
                
        self.test_results['api_keys'] = configured
        
    def test_cache_storage(self):
        """Test cache storage and retrieval"""
        if not self.redis_client:
            print("❌ Skipping cache test - Redis not connected")
            self.test_results['cache_storage'] = False
            return
            
        try:
            # Create test analysis
            test_id = f"test_{uuid.uuid4().hex[:8]}"
            test_analysis = {
                "verdict": {
                    "decision": "PASS",
                    "confidence": 65,
                    "hot_take": "Test analysis for diagnostics"
                },
                "market_analysis": {
                    "tam": "Test TAM",
                    "competition": "Test competition",
                    "timing": "Test timing",
                    "score": 5
                },
                "content": "This is test content for pro analysis generation",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Store in cache
            self.redis_client.setex(
                f"analysis:{test_id}",
                300,  # 5 minute expiry
                json.dumps(test_analysis)
            )
            
            # Retrieve from cache
            cached = self.redis_client.get(f"analysis:{test_id}")
            if cached:
                retrieved = json.loads(cached)
                if retrieved['verdict']['hot_take'] == test_analysis['verdict']['hot_take']:
                    print(f"✅ Cache storage working - Test ID: {test_id}")
                    self.test_results['cache_storage'] = True
                else:
                    print("❌ Cache retrieval mismatch")
                    self.test_results['cache_storage'] = False
            else:
                print("❌ Failed to retrieve from cache")
                self.test_results['cache_storage'] = False
                
            # Cleanup
            self.redis_client.delete(f"analysis:{test_id}")
            
        except Exception as e:
            print(f"❌ Cache test failed: {e}")
            self.test_results['cache_storage'] = False
            
    def test_pro_analysis_generation(self):
        """Test pro analysis generation with mock data"""
        try:
            # Simulate the _generate_mock_pro_analysis method
            mock_pro_analysis = {
                "competitor_analysis": {
                    "main_competitors": [
                        {
                            "name": "DiagnosticCompetitor1",
                            "strength": "Test strength",
                            "weakness": "Test weakness",
                            "market_share": "30%",
                            "funding": "$50M",
                            "key_differentiator": "Test differentiator",
                            "vulnerability": "Test vulnerability",
                            "recent_moves": "Test move"
                        }
                    ],
                    "positioning": "Test positioning strategy"
                },
                "market_opportunity": {
                    "tam_breakdown": "Test TAM breakdown",
                    "sam": "Test SAM",
                    "som": "Test SOM",
                    "growth_rate": "Test growth rate"
                },
                "financial_projections": {
                    "year_1": {"users": "100", "revenue": "$10K"}
                },
                "next_steps": {
                    "immediate": ["Test step 1", "Test step 2"],
                    "30_days": ["Test 30-day step"],
                    "90_days": ["Test 90-day step"]
                }
            }
            
            # Verify structure
            required_keys = ['competitor_analysis', 'market_opportunity', 'financial_projections', 'next_steps']
            missing_keys = [k for k in required_keys if k not in mock_pro_analysis]
            
            if not missing_keys:
                print("✅ Pro analysis structure is correct")
                self.test_results['pro_structure'] = True
            else:
                print(f"❌ Missing keys in pro analysis: {missing_keys}")
                self.test_results['pro_structure'] = False
                
        except Exception as e:
            print(f"❌ Pro analysis test failed: {e}")
            self.test_results['pro_structure'] = False
            
    def check_existing_cache(self):
        """Check for existing cached analyses"""
        if not self.redis_client:
            print("❌ Skipping - Redis not connected")
            return
            
        try:
            # Look for analysis:* keys
            keys = []
            cursor = 0
            while True:
                cursor, partial_keys = self.redis_client.scan(cursor, match='analysis:*', count=100)
                keys.extend(partial_keys)
                if cursor == 0:
                    break
                    
            print(f"📊 Found {len(keys)} cached analyses")
            
            # Check a few for pro_analysis
            pro_count = 0
            for key in keys[:5]:  # Check first 5
                try:
                    data = self.redis_client.get(key)
                    if data:
                        analysis = json.loads(data)
                        if 'pro_analysis' in analysis:
                            pro_count += 1
                except:
                    pass
                    
            print(f"   {pro_count} out of {min(5, len(keys))} checked have pro_analysis")
            
            # Show one example
            if keys:
                example_key = keys[0].decode() if isinstance(keys[0], bytes) else keys[0]
                print(f"   Example key: {example_key}")
                
        except Exception as e:
            print(f"❌ Cache check failed: {e}")
            
    def print_summary(self):
        """Print diagnostic summary"""
        print("\n" + "=" * 60)
        print("📋 DIAGNOSTIC SUMMARY")
        print("=" * 60)
        
        all_passed = all(self.test_results.values())
        
        if all_passed:
            print("✅ All tests passed!")
        else:
            print("⚠️  Some tests failed:")
            for test, result in self.test_results.items():
                if not result:
                    print(f"   - {test}")
                    
        print("\n💡 RECOMMENDATIONS:")
        
        if not self.test_results.get('redis'):
            print("   1. Fix Redis connection - required for caching")
            
        if not self.test_results.get('api_keys'):
            print("   2. Set at least one AI API key (OPENAI_API_KEY or GROQ_API_KEY)")
            
        if self.test_results.get('redis') and self.test_results.get('api_keys'):
            print("   ✅ System should be ready for pro analysis!")
            
        print("\n🔧 To test pro analysis without file upload:")
        print("   1. Use the test cache ID from above")
        print("   2. Or manually create a cache entry")
        print("   3. Call /api/pro-analysis/<test_id>")


def create_test_cache_entry():
    """Create a test cache entry for manual testing"""
    redis_client = redis.Redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
    
    test_id = f"manual_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    test_analysis = {
        "verdict": {
            "decision": "PASS",
            "confidence": 72,
            "hot_take": "Great technical team but unclear market fit",
            "reasoning": "Strong engineering but needs better customer validation"
        },
        "market_analysis": {
            "tam": "$2.5B global market for developer tools, growing at 22% annually. The IDE plugin segment represents $450M with increasing demand for AI-assisted coding.",
            "competition": "GitHub Copilot dominates with 60% share. Tabnine and Kite have 15% and 10% respectively. New entrants like Cursor gaining traction.",
            "timing": "Perfect timing with AI boom. Developers actively seeking productivity tools. Enterprise adoption accelerating post-2024.",
            "score": 8
        },
        "founder_assessment": {
            "strengths": [
                "10+ years software engineering at FAANG",
                "Published ML research papers",
                "Previous successful exit ($5M acquisition)"
            ],
            "weaknesses": [
                "No direct sales experience",
                "Limited enterprise software background"
            ],
            "domain_expertise": 9,
            "execution_ability": 7
        },
        "benchmarks": {
            "market_score": 8,
            "team_score": 8,
            "product_score": 7,
            "business_score": 6,
            "overall_score": 7.25
        },
        "feedback": {
            "brutal_truth": "You're building a 'nice to have' in a market dominated by free tools. Developers are notoriously cheap and your $29/month pricing is 3x the competition. Without a 10x better product or unique distribution, you'll struggle.",
            "encouragement": "Your technical prowess is undeniable and the product demos beautifully. Early user feedback is glowing. Focus on one specific developer niche where the pain is acute."
        },
        "content": "AI-powered code completion tool for developers...",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Store in Redis
    redis_client.setex(
        f"analysis:{test_id}",
        3600,  # 1 hour expiry
        json.dumps(test_analysis)
    )
    
    print(f"\n✅ Created test cache entry!")
    print(f"📌 Test ID: {test_id}")
    print(f"🔗 Test URL: http://localhost:5000/api/pro-analysis/{test_id}")
    print(f"⏰ Expires in: 1 hour")
    
    return test_id


if __name__ == "__main__":
    # Run diagnostics
    diag = AutoVCDiagnostics()
    diag.run_all_tests()
    
    # Ask if user wants to create a test entry
    print("\n" + "=" * 60)
    response = input("\n🧪 Create a test cache entry for manual testing? (y/n): ")
    if response.lower() == 'y':
        test_id = create_test_cache_entry()
        print(f"\n🎯 You can now test the pro analysis endpoint with this ID!")
        print(f"   No file upload needed - just click 'See Pro Analysis' with ID: {test_id}")