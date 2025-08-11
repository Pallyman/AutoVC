# pro_analyzer.py
"""
Enhanced Pro Analysis Module for AutoVC
Uses actual AI insights instead of generic templates
"""

from typing import Dict, Any, List
import logging
import re

logger = logging.getLogger(__name__)


class ProAnalyzer:
    """
    Enhanced ProAnalyzer that builds on actual AI insights
    instead of using generic templates
    """
    
    def __init__(self, full_analysis: Dict[str, Any]):
        self.analysis = full_analysis
        
    def get_insights(self) -> Dict[str, Any]:
        """
        Extracts or generates the pro insights from the main analysis.
        Returns a complete pro_analysis section.
        """
        # If pro_analysis already exists and is complete, return it
        if self._has_complete_pro_analysis():
            return self.analysis["pro_analysis"]
        
        # Otherwise, generate comprehensive pro insights
        return self._generate_pro_insights()
    
    def _has_complete_pro_analysis(self) -> bool:
        """Check if the analysis already has a complete pro_analysis section"""
        if "pro_analysis" not in self.analysis:
            return False
            
        pro = self.analysis["pro_analysis"]
        required_keys = ["competitor_analysis", "market_opportunity", "financial_projections", "next_steps"]
        
        return all(key in pro and pro[key] for key in required_keys)
    
    def _generate_pro_insights(self) -> Dict[str, Any]:
        """
        Generates comprehensive pro insights based on the ACTUAL AI analysis
        """
        # Extract ALL the AI's insights
        verdict = self.analysis.get("verdict", {})
        market = self.analysis.get("market_analysis", {})
        benchmarks = self.analysis.get("benchmarks", {})
        feedback = self.analysis.get("feedback", {})
        product = self.analysis.get("product_analysis", {})
        business = self.analysis.get("business_model", {})
        founders = self.analysis.get("founder_assessment", {})
        
        # Get context from AI's actual analysis
        market_score = benchmarks.get("market_score", 5)
        is_fundable = verdict.get("decision") == "FUND"
        
        # Generate insights based on ACTUAL AI content
        competitors = self._generate_competitor_analysis_from_ai(market, market_score)
        market_opp = self._generate_market_opportunity_from_ai(market, business, market_score)
        financials = self._generate_financial_projections_from_ai(business, market_score, is_fundable)
        next_steps = self._generate_next_steps_from_ai(feedback, founders, product, benchmarks)
        
        return {
            "competitor_analysis": competitors,
            "market_opportunity": market_opp,
            "financial_projections": financials,
            "next_steps": next_steps
        }
    
    def _generate_competitor_analysis_from_ai(self, market: Dict, market_score: int) -> Dict[str, Any]:
        """Generate competitor analysis based on AI's actual market analysis"""
        
        # Extract competitor info from AI's competition analysis
        competition_text = market.get("competition", "")
        
        # Try to extract company names from the AI's analysis
        # Look for patterns like "Company X", "Inc", "Corp", etc.
        company_pattern = r'([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*(?:\s+(?:Corp|Inc|Ltd|LLC|Co|Company|Labs|AI|Tech|Technologies))?)'
        mentioned_companies = re.findall(company_pattern, competition_text)[:3]  # Get top 3
        
        competitors = []
        
        # If AI mentioned specific companies, use them
        if mentioned_companies and len(mentioned_companies) > 0:
            for company_name in mentioned_companies:
                # Build competitor profile based on what AI said
                competitor = {
                    "name": company_name,
                    "strength": self._extract_strength_from_text(competition_text, company_name),
                    "weakness": self._infer_weakness(market_score),
                    "market_share": self._estimate_market_share(len(mentioned_companies), mentioned_companies.index(company_name)),
                    "funding": self._estimate_funding_stage(market_score),
                    "key_differentiator": self._extract_differentiator(competition_text),
                    "vulnerability": self._infer_vulnerability(market_score),
                    "recent_moves": "Expanding product offerings and geographical presence"
                }
                competitors.append(competitor)
        
        # If no specific companies found, generate based on market dynamics
        if not competitors:
            if market_score >= 7:
                competitors = self._generate_high_growth_competitors()
            elif market_score >= 5:
                competitors = self._generate_moderate_competitors()
            else:
                competitors = self._generate_tough_market_competitors()
        
        # Generate positioning based on AI's actual advice
        positioning = self._extract_positioning_strategy(market, competition_text)
        
        return {
            "main_competitors": competitors,
            "positioning": positioning
        }
    
    def _generate_market_opportunity_from_ai(self, market: Dict, business: Dict, market_score: int) -> Dict[str, Any]:
        """Generate market opportunity based on AI's actual TAM analysis"""
        
        tam_text = market.get("tam", "")
        
        # Try to extract numbers from AI's TAM analysis
        numbers = re.findall(r'\$[\d.]+[BMK]|\d+%', tam_text)
        
        # Extract growth rate if mentioned
        growth_pattern = r'(\d+)%\s*(?:CAGR|growth|annually)'
        growth_match = re.search(growth_pattern, tam_text, re.IGNORECASE)
        growth_rate = f"{growth_match.group(1)}% CAGR" if growth_match else "15% estimated CAGR"
        
        # Build TAM breakdown from AI's analysis
        tam_breakdown = tam_text if tam_text else f"Market estimated at ${market_score * 2}B with strong growth potential"
        
        # Calculate SAM and SOM based on AI's assessment
        if numbers and len(numbers) > 0:
            # Use actual numbers from AI
            sam = f"Serviceable market of {numbers[0] if len(numbers) > 0 else '$1B'} based on target segments"
            som = f"Realistic capture of 1-5% of SAM within 3 years through focused execution"
        else:
            # Estimate based on scores
            sam = f"${market_score * 100}M serviceable market in target segments"
            som = f"${market_score * 5}M realistic capture in 3 years"
        
        return {
            "tam_breakdown": tam_breakdown,
            "sam": sam,
            "som": som,
            "growth_rate": f"Market growing at {growth_rate}"
        }
    
    def _generate_financial_projections_from_ai(self, business: Dict, market_score: int, is_fundable: bool) -> Dict[str, Any]:
        """Generate financial projections based on AI's business model analysis"""
        
        revenue_model = business.get("revenue_model", "")
        unit_economics = business.get("unit_economics", "")
        
        # Try to extract pricing from AI's analysis
        price_pattern = r'\$(\d+)(?:/month|/user|/year)'
        price_match = re.search(price_pattern, revenue_model)
        
        # Base projections on AI's assessment
        if "SaaS" in revenue_model or "subscription" in revenue_model.lower():
            # SaaS model projections
            base_price = int(price_match.group(1)) if price_match else 99
            
            if is_fundable and market_score >= 7:
                return {
                    "year_1": {"users": "1,000", "revenue": f"${base_price * 12 * 1000 / 1000}K", "burn": "$2M"},
                    "year_2": {"users": "5,000", "revenue": f"${base_price * 12 * 5000 / 1000}K", "burn": "$3M"},
                    "year_3": {"users": "20,000", "revenue": f"${base_price * 12 * 20000 / 1000}K", "burn": "$1M"}
                }
            else:
                return {
                    "year_1": {"users": "200", "revenue": f"${base_price * 12 * 200 / 1000}K", "burn": "$800K"},
                    "year_2": {"users": "1,000", "revenue": f"${base_price * 12 * 1000 / 1000}K", "burn": "$600K"},
                    "year_3": {"users": "3,500", "revenue": f"${base_price * 12 * 3500 / 1000}K", "burn": "$200K"}
                }
        else:
            # Generic projections for other models
            return self._generate_default_projections(is_fundable, market_score)
    
    def _generate_next_steps_from_ai(self, feedback: Dict, founders: Dict, product: Dict, benchmarks: Dict) -> Dict[str, Any]:
        """Generate next steps based on AI's actual feedback and recommendations"""
        
        # Get AI's specific action items
        ai_action_items = feedback.get("action_items", [])
        ai_risks = feedback.get("key_risks", [])
        
        immediate_actions = []
        thirty_day_actions = []
        ninety_day_actions = []
        
        # Use AI's actual action items first
        for i, action in enumerate(ai_action_items):
            if i == 0:
                immediate_actions.append(action)
            elif i == 1:
                thirty_day_actions.append(action)
            else:
                ninety_day_actions.append(action)
        
        # Add actions based on AI's identified weaknesses
        weaknesses = founders.get("weaknesses", [])
        for weakness in weaknesses[:2]:
            if "sales" in weakness.lower():
                thirty_day_actions.append("Hire experienced sales leader to address go-to-market gaps")
            elif "technical" in weakness.lower():
                immediate_actions.append("Recruit senior technical advisor or CTO")
            elif "industry" in weakness.lower():
                immediate_actions.append("Build advisory board with industry veterans")
        
        # Add actions based on AI's identified risks
        for risk in ai_risks[:2]:
            if "market" in risk.lower():
                immediate_actions.append("Conduct deeper market validation with 20+ customer interviews")
            elif "competition" in risk.lower():
                thirty_day_actions.append("Develop clear competitive differentiation strategy")
            elif "unit economics" in risk.lower():
                immediate_actions.append("Optimize pricing model to improve unit economics")
        
        # Add product-specific actions
        problem_validation = product.get("problem_validation", "")
        if "weak" in problem_validation.lower() or "unclear" in problem_validation.lower():
            immediate_actions.append("Run problem validation sprint with target customers")
        
        # Ensure we have enough actions
        while len(immediate_actions) < 5:
            immediate_actions.append(self._get_default_action("immediate", benchmarks))
        while len(thirty_day_actions) < 5:
            thirty_day_actions.append(self._get_default_action("30_days", benchmarks))
        while len(ninety_day_actions) < 5:
            ninety_day_actions.append(self._get_default_action("90_days", benchmarks))
        
        return {
            "immediate": immediate_actions[:5],
            "30_days": thirty_day_actions[:5],
            "90_days": ninety_day_actions[:5]
        }
    
    # Helper methods
    def _extract_strength_from_text(self, text: str, company: str) -> str:
        """Extract strength mentioned about a company"""
        sentences = text.split('.')
        for sentence in sentences:
            if company in sentence:
                # Look for positive indicators
                if any(word in sentence.lower() for word in ['lead', 'dominant', 'strong', 'best']):
                    return sentence.strip()
        return "Established market presence with proven product-market fit"
    
    def _infer_weakness(self, market_score: int) -> str:
        """Infer weakness based on market dynamics"""
        if market_score >= 7:
            return "May be slow to adapt to rapid market changes"
        elif market_score >= 5:
            return "Limited innovation budget compared to new entrants"
        else:
            return "High customer acquisition costs in mature market"
    
    def _estimate_market_share(self, total_competitors: int, position: int) -> str:
        """Estimate market share based on position"""
        if position == 0:
            return "40-60%"
        elif position == 1:
            return "20-30%"
        else:
            return "10-20%"
    
    def _estimate_funding_stage(self, market_score: int) -> str:
        """Estimate typical funding based on market maturity"""
        if market_score >= 7:
            return "$50M+ Series B/C"
        elif market_score >= 5:
            return "$20M Series A/B"
        else:
            return "$100M+ or Public"
    
    def _extract_differentiator(self, text: str) -> str:
        """Extract key differentiator from competition text"""
        if "platform" in text.lower():
            return "Comprehensive platform approach"
        elif "ai" in text.lower() or "ml" in text.lower():
            return "Advanced AI/ML capabilities"
        elif "price" in text.lower():
            return "Competitive pricing model"
        else:
            return "Superior user experience and customer service"
    
    def _infer_vulnerability(self, market_score: int) -> str:
        """Infer vulnerability based on market dynamics"""
        if market_score >= 7:
            return "Vulnerable to well-funded new entrants with innovative approaches"
        else:
            return "High burn rate requiring continuous funding"
    
    def _extract_positioning_strategy(self, market: Dict, competition_text: str) -> str:
        """Extract positioning strategy from AI's analysis"""
        timing = market.get("timing", "")
        
        if "early" in timing.lower() or "emerging" in timing.lower():
            return "Position as the innovation leader and first-mover in emerging category"
        elif "mature" in timing.lower():
            return "Focus on underserved niches where incumbents have weak presence"
        else:
            return competition_text[-200:] if len(competition_text) > 200 else "Differentiate through superior execution and customer experience"
    
    def _generate_default_projections(self, is_fundable: bool, market_score: int) -> Dict[str, Any]:
        """Fallback projections"""
        if is_fundable and market_score >= 7:
            return {
                "year_1": {"users": "1,000", "revenue": "$250K", "burn": "$2M"},
                "year_2": {"users": "5,000", "revenue": "$1.5M", "burn": "$3M"},
                "year_3": {"users": "15,000", "revenue": "$5M", "burn": "$2M"}
            }
        else:
            return {
                "year_1": {"users": "100", "revenue": "$50K", "burn": "$500K"},
                "year_2": {"users": "500", "revenue": "$250K", "burn": "$400K"},
                "year_3": {"users": "1,500", "revenue": "$750K", "burn": "$200K"}
            }
    
    def _get_default_action(self, timeframe: str, benchmarks: Dict) -> str:
        """Get default action based on timeframe"""
        if timeframe == "immediate":
            return "Set up weekly metrics review and KPI tracking"
        elif timeframe == "30_days":
            return "Establish product-market fit validation process"
        else:
            return "Build scalable go-to-market engine"
    
    # Keep the original template methods as fallbacks
    def _generate_high_growth_competitors(self) -> List[Dict]:
        """Fallback for high growth markets"""
        return [
            {
                "name": "Market Leader",
                "strength": "Dominant market position with strong network effects",
                "weakness": "Legacy technology and slow innovation",
                "market_share": "45%",
                "funding": "$100M+ raised",
                "key_differentiator": "First mover advantage and brand recognition",
                "vulnerability": "Disruption from new technologies",
                "recent_moves": "Acquiring smaller competitors"
            }
        ]
    
    def _generate_moderate_competitors(self) -> List[Dict]:
        """Fallback for moderate markets"""
        return [
            {
                "name": "Established Player",
                "strength": "Solid product-market fit",
                "weakness": "Limited innovation budget",
                "market_share": "30%",
                "funding": "$50M raised",
                "key_differentiator": "Industry expertise",
                "vulnerability": "New entrants with fresh capital",
                "recent_moves": "Expanding internationally"
            }
        ]
    
    def _generate_tough_market_competitors(self) -> List[Dict]:
        """Fallback for tough markets"""
        return [
            {
                "name": "Dominant Incumbent",
                "strength": "Massive scale and resources",
                "weakness": "Slow to innovate",
                "market_share": "70%",
                "funding": "Public company",
                "key_differentiator": "Complete solution suite",
                "vulnerability": "Regulatory changes",
                "recent_moves": "Cost cutting and optimization"
            }
        ]