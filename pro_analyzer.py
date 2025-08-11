# pro_analyzer.py
"""
AI-First ProAnalyzer Module for AutoVC
Prefers actual AI analysis data, falls back to templates only when needed
"""

from typing import Dict, Any, List, Optional
import logging
import re
import json

logger = logging.getLogger(__name__)


class ProAnalyzer:
    """
    AI-First ProAnalyzer that extracts from actual AI analysis
    Falls back to templates only when AI data is thin
    """
    
    def __init__(self, full_analysis: Dict[str, Any]):
        self.analysis = full_analysis
        self.market_context = self._determine_market_context()
        
    def _determine_market_context(self) -> str:
        """Determine the market context from AI analysis"""
        # Combine all text from AI analysis
        all_text = json.dumps(self.analysis).lower()
        
        # Industry detection with priority order
        if any(word in all_text for word in ['saas', 'software as a service', 'b2b software']):
            return 'saas'
        elif any(word in all_text for word in ['fintech', 'payment', 'banking', 'financial technology']):
            return 'fintech'
        elif any(word in all_text for word in ['artificial intelligence', 'machine learning', 'llm', 'generative ai']):
            return 'ai'
        elif any(word in all_text for word in ['marketplace', 'ecommerce', 'e-commerce', 'retail']):
            return 'marketplace'
        elif any(word in all_text for word in ['healthcare', 'health tech', 'medical', 'biotech']):
            return 'healthcare'
        else:
            return 'tech'
    
    def get_insights(self) -> Dict[str, Any]:
        """Get pro insights - prefer AI data, fallback to generation"""
        # Check if AI already provided pro_analysis
        if self._has_complete_pro_analysis():
            logger.info("Using AI-provided pro_analysis")
            return self.analysis["pro_analysis"]
        
        # Generate insights using AI data first, templates as fallback
        return self._generate_pro_insights()
    
    def _has_complete_pro_analysis(self) -> bool:
        """Check if the analysis already has a complete pro_analysis section"""
        if "pro_analysis" not in self.analysis:
            return False
            
        pro = self.analysis["pro_analysis"]
        required_keys = ["competitor_analysis", "market_opportunity", "financial_projections", "next_steps"]
        
        return all(key in pro and pro[key] for key in required_keys)
    
    def _generate_pro_insights(self) -> Dict[str, Any]:
        """Generate pro insights preferring AI data over templates"""
        
        verdict = self.analysis.get("verdict", {})
        market = self.analysis.get("market_analysis", {})
        benchmarks = self.analysis.get("benchmarks", {})
        business = self.analysis.get("business_model", {})
        feedback = self.analysis.get("feedback", {})
        
        market_score = benchmarks.get("market_score", 5)
        is_fundable = verdict.get("decision") == "FUND"
        
        return {
            "competitor_analysis": self._generate_competitor_analysis(market, market_score),
            "market_opportunity": self._generate_market_opportunity(market, business, market_score),
            "financial_projections": self._generate_financial_projections(business, benchmarks, is_fundable),
            "next_steps": self._generate_next_steps(feedback, benchmarks, is_fundable)
        }
    
    def _generate_competitor_analysis(self, market: Dict, market_score: int) -> Dict[str, Any]:
        """Extract competitors from AI analysis first, fallback to templates"""
        
        # 1. First, check if AI provided structured competitor data
        if "competitors" in market and isinstance(market["competitors"], list):
            logger.info("Using AI-provided competitor list")
            competitors = market["competitors"][:3]
            positioning = market.get("positioning", self._generate_positioning(market_score))
            return {
                "main_competitors": competitors,
                "positioning": positioning
            }
        
        # 2. Try to extract competitors from competition text
        competition_text = market.get("competition", "")
        extracted_competitors = self._extract_competitors_from_text(competition_text, market)
        
        if extracted_competitors:
            logger.info(f"Extracted {len(extracted_competitors)} competitors from AI text")
            positioning = self._extract_positioning_from_text(competition_text, market)
            return {
                "main_competitors": extracted_competitors,
                "positioning": positioning
            }
        
        # 3. Fallback to template competitors
        logger.info("Using template competitors as fallback")
        return self._get_template_competitors(market_score)
    
    def _extract_competitors_from_text(self, competition_text: str, market: Dict) -> List[Dict]:
        """Extract competitor information from AI's competition analysis"""
        competitors = []
        
        # Pattern to find company names (capitalized words often followed by Inc, Corp, etc.)
        company_pattern = r'([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*(?:\s+(?:Corp|Inc|Ltd|LLC|Co|Company|Labs|AI|Tech|Technologies|Systems|Platform|Software))?)'
        potential_companies = re.findall(company_pattern, competition_text)
        
        # Filter out generic terms
        generic_terms = ['The', 'This', 'These', 'Their', 'Market', 'Industry', 'Technology', 'Customer', 'Product']
        companies = [c for c in potential_companies if c not in generic_terms and len(c) > 3][:3]
        
        for company in companies:
            competitor = {
                "name": company,
                "strength": self._extract_strength(company, competition_text),
                "weakness": self._extract_weakness(company, competition_text, market_score),
                "market_share": self._extract_market_share(company, competition_text),
                "funding": self._extract_funding(company, competition_text),
                "key_differentiator": self._extract_differentiator(company, competition_text),
                "vulnerability": self._extract_vulnerability(company, competition_text, market_score),
                "recent_moves": self._extract_recent_moves(company, competition_text)
            }
            competitors.append(competitor)
        
        return competitors
    
    def _extract_strength(self, company: str, text: str) -> str:
        """Extract or infer strength for a company"""
        sentences = text.split('.')
        for sentence in sentences:
            if company in sentence:
                if any(word in sentence.lower() for word in ['strong', 'lead', 'dominat', 'best', 'top']):
                    return sentence.strip()[:100]
        
        # Default based on position
        if text.find(company) < 100:  # Mentioned early, likely leader
            return "Market leader with strong brand recognition and customer base"
        return "Established player with proven product-market fit"
    
    def _extract_weakness(self, company: str, text: str, market_score: int) -> str:
        """Extract or infer weakness"""
        sentences = text.split('.')
        for sentence in sentences:
            if company in sentence:
                if any(word in sentence.lower() for word in ['weak', 'slow', 'lack', 'struggle', 'behind']):
                    return sentence.strip()[:100]
        
        # Infer based on market dynamics
        if market_score >= 7:
            return "Slower innovation cycles compared to nimble startups"
        return "High customer acquisition costs and legacy technical debt"
    
    def _extract_market_share(self, company: str, text: str) -> str:
        """Extract market share if mentioned"""
        # Look for percentages near company name
        pattern = f"{company}.*?(\\d+)%|{company}.*?market share.*?(\\d+)%|(\\d+)%.*?{company}"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            percent = match.group(1) or match.group(2) or match.group(3)
            return f"{percent}%"
        
        # Infer based on mention order
        companies_mentioned = re.findall(r'([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)', text)
        if companies_mentioned.index(company) == 0:
            return "30-50%"
        elif companies_mentioned.index(company) == 1:
            return "15-25%"
        return "5-15%"
    
    def _extract_funding(self, company: str, text: str) -> str:
        """Extract funding information if mentioned"""
        # Look for funding amounts near company
        pattern = f"{company}.*?\\$([\\d.]+[BMK])|\\$([\\d.]+[BMK]).*?{company}"
        match = re.search(pattern, text)
        if match:
            amount = match.group(1) or match.group(2)
            return f"${amount} raised"
        
        # Look for IPO/public mentions
        if any(word in text.lower() for word in ['public', 'ipo', 'nasdaq', 'nyse']):
            return "Public company"
        
        return "Well-funded (undisclosed)"
    
    def _extract_differentiator(self, company: str, text: str) -> str:
        """Extract key differentiator"""
        sentences = text.split('.')
        for sentence in sentences:
            if company in sentence:
                if any(word in sentence.lower() for word in ['platform', 'solution', 'technology', 'approach']):
                    return sentence.strip()[:100]
        
        return "Comprehensive solution with strong market presence"
    
    def _extract_vulnerability(self, company: str, text: str, market_score: int) -> str:
        """Extract or infer vulnerability"""
        if "disrupt" in text.lower():
            return "Vulnerable to disruption from AI-native startups"
        elif "legacy" in text.lower():
            return "Legacy architecture limiting agility"
        elif market_score >= 7:
            return "High burn rate requiring continuous funding"
        return "Market saturation limiting growth potential"
    
    def _extract_recent_moves(self, company: str, text: str) -> str:
        """Extract recent strategic moves"""
        if "acqui" in text.lower():
            return "Recent acquisitions to expand capabilities"
        elif "launch" in text.lower():
            return "Launched new product lines to capture market share"
        elif "partner" in text.lower():
            return "Strategic partnerships to accelerate growth"
        return "Expanding product offerings and geographical reach"
    
    def _extract_positioning_from_text(self, competition_text: str, market: Dict) -> str:
        """Extract positioning strategy from AI analysis"""
        timing = market.get("timing", "")
        
        # Look for positioning keywords in the text
        if "differentiat" in competition_text.lower():
            # Find the sentence with differentiation
            sentences = competition_text.split('.')
            for sentence in sentences:
                if "differentiat" in sentence.lower():
                    return sentence.strip()
        
        # Use timing to infer positioning
        if "early" in timing.lower():
            return "Position as the next-generation solution with 10x better speed and user experience"
        elif "mature" in timing.lower():
            return "Focus on underserved niches where incumbents have weak presence"
        
        # Default positioning
        return "Differentiate through superior execution, customer success, and modern technology stack"
    
    def _generate_market_opportunity(self, market: Dict, business: Dict, market_score: int) -> Dict[str, Any]:
        """Generate market opportunity - prefer AI data over templates"""
        
        # 1. Check if AI provided structured market data
        if all(key in market for key in ["tam_breakdown", "sam", "som"]):
            logger.info("Using AI-provided market opportunity data")
            return {
                "tam_breakdown": market["tam_breakdown"],
                "sam": market["sam"],
                "som": market["som"],
                "growth_rate": market.get("growth_rate", self._extract_growth_rate(market))
            }
        
        # 2. Extract from TAM text
        tam_text = market.get("tam", "")
        tam_breakdown = self._enhance_tam_with_details(tam_text, market_score)
        sam = self._calculate_sam_from_tam(tam_text, business, market_score)
        som = self._calculate_som_from_sam(sam, market_score)
        growth_rate = self._extract_growth_rate(market)
        
        return {
            "tam_breakdown": tam_breakdown,
            "sam": sam,
            "som": som,
            "growth_rate": growth_rate
        }
    
    def _enhance_tam_with_details(self, tam_text: str, market_score: int) -> str:
        """Enhance TAM text with additional details"""
        if not tam_text:
            return self._get_template_tam(market_score)
        
        # Extract numbers from TAM
        numbers = re.findall(r'\$[\d.]+[BMK]', tam_text)
        growth = re.search(r'(\d+)%\s*(?:CAGR|growth)', tam_text)
        
        if numbers:
            tam_value = numbers[0]
            growth_text = f", {growth.group(0)}" if growth else ", growing double-digit"
            
            # Add regional breakdown if not present
            if "north america" not in tam_text.lower():
                return f"{tam_text} (NA: 40%, EU: 30%, APAC: 25%, RoW: 5%){growth_text}"
            return f"{tam_text}{growth_text}"
        
        return tam_text or self._get_template_tam(market_score)
    
    def _calculate_sam_from_tam(self, tam_text: str, business: Dict, market_score: int) -> str:
        """Calculate SAM from TAM and business model"""
        # Extract TAM value
        tam_match = re.search(r'\$?([\d.]+)([BMK])', tam_text)
        if tam_match:
            value = float(tam_match.group(1))
            unit = tam_match.group(2)
            
            # Convert to millions
            if unit == 'B':
                value *= 1000
            elif unit == 'K':
                value /= 1000
            
            # Calculate SAM as percentage of TAM based on focus
            sam_percent = 0.2 if market_score >= 7 else 0.15 if market_score >= 5 else 0.1
            sam_value = value * sam_percent
            
            # Format appropriately
            if sam_value >= 1000:
                return f"${sam_value/1000:.1f}B serviceable addressable market in target segments"
            return f"${sam_value:.0f}M serviceable market focusing on {self._get_target_segment()}"
        
        # Fallback
        return f"${market_score * 100}M addressable market in core segments"
    
    def _calculate_som_from_sam(self, sam: str, market_score: int) -> str:
        """Calculate SOM from SAM"""
        # Extract SAM value
        sam_match = re.search(r'\$?([\d.]+)([BMK])', sam)
        if sam_match:
            value = float(sam_match.group(1))
            unit = sam_match.group(2)
            
            # Convert to millions
            if unit == 'B':
                value *= 1000
            elif unit == 'K':
                value /= 1000
            
            # Calculate SOM as 3-5% of SAM
            som_percent = 0.05 if market_score >= 7 else 0.03
            som_value = value * som_percent
            
            return f"${som_value:.1f}M realistic capture in 3 years through focused execution"
        
        # Fallback
        return f"${market_score * 5}M achievable market share within 36 months"
    
    def _extract_growth_rate(self, market: Dict) -> str:
        """Extract growth rate from market analysis"""
        tam_text = market.get("tam", "")
        timing_text = market.get("timing", "")
        
        # Look for CAGR or growth percentages
        growth_match = re.search(r'(\d+)%\s*(?:CAGR|growth|annually)', tam_text + timing_text, re.IGNORECASE)
        if growth_match:
            return f"Market growing at {growth_match.group(1)}% CAGR"
        
        # Infer from timing
        if "rapid" in timing_text.lower() or "accelerat" in timing_text.lower():
            return "Market experiencing rapid growth (25%+ CAGR)"
        elif "mature" in timing_text.lower():
            return "Mature market with single-digit growth, opportunity in share capture"
        
        return "Market growing at 15-20% annually driven by digital transformation"
    
    def _generate_financial_projections(self, business: Dict, benchmarks: Dict, is_fundable: bool) -> Dict[str, Any]:
        """Generate projections based on AI's business model analysis"""
        
        # 1. Check if AI provided projections
        if "projections" in business:
            logger.info("Using AI-provided financial projections")
            return business["projections"]
        
        # 2. Extract pricing and model details
        revenue_text = business.get("revenue_model", "")
        unit_economics = business.get("unit_economics", "")
        
        # Extract key metrics
        price = self._extract_price(revenue_text)
        cac = self._extract_cac(unit_economics)
        ltv = self._extract_ltv(unit_economics)
        
        market_score = benchmarks.get("market_score", 5)
        
        # Generate realistic projections based on extracted data
        return self._calculate_projections(price, cac, ltv, market_score, is_fundable)
    
    def _extract_price(self, revenue_text: str) -> int:
        """Extract pricing from revenue model"""
        price_match = re.search(r'\$(\d+)(?:/month|/user|/year)?', revenue_text)
        if price_match:
            return int(price_match.group(1))
        
        # Look for SaaS, enterprise, SMB keywords to infer
        if "enterprise" in revenue_text.lower():
            return 500
        elif "smb" in revenue_text.lower():
            return 99
        return 199  # Default mid-market
    
    def _extract_cac(self, unit_economics: str) -> int:
        """Extract CAC from unit economics"""
        cac_match = re.search(r'CAC.*?\$(\d+)', unit_economics, re.IGNORECASE)
        if cac_match:
            return int(cac_match.group(1))
        return 2000  # Default
    
    def _extract_ltv(self, unit_economics: str) -> int:
        """Extract LTV from unit economics"""
        ltv_match = re.search(r'LTV.*?\$(\d+)', unit_economics, re.IGNORECASE)
        if ltv_match:
            return int(ltv_match.group(1))
        return 6000  # Default 3:1 ratio
    
    def _calculate_projections(self, price: int, cac: int, ltv: int, market_score: int, is_fundable: bool) -> Dict[str, Any]:
        """Calculate realistic projections based on metrics"""
        
        # Base user growth on market dynamics and fundability
        if is_fundable and market_score >= 7:
            year1_users = 2000 + (market_score * 100)
            growth_rate = 4.5  # 4.5x year over year
        elif market_score >= 5:
            year1_users = 500 + (market_score * 50)
            growth_rate = 3.0
        else:
            year1_users = 100 + (market_score * 20)
            growth_rate = 2.5
        
        # Calculate for each year
        return {
            "year_1": {
                "users": f"{year1_users:,}",
                "revenue": f"${(year1_users * price * 12 / 1000):.0f}K",
                "burn": f"${(year1_users * cac / 1000):.1f}M"
            },
            "year_2": {
                "users": f"{int(year1_users * growth_rate):,}",
                "revenue": f"${(year1_users * growth_rate * price * 12 / 1000):.0f}K",
                "burn": f"${(year1_users * growth_rate * cac * 0.7 / 1000):.1f}M"  # Improving efficiency
            },
            "year_3": {
                "users": f"{int(year1_users * growth_rate * growth_rate):,}",
                "revenue": f"${(year1_users * growth_rate * growth_rate * price * 12 / 1000000):.1f}M",
                "burn": f"${max(0, (year1_users * growth_rate * growth_rate * cac * 0.4 / 1000) - (year1_users * growth_rate * growth_rate * price * 12 / 1000000)):.1f}M"
            }
        }
    
    def _generate_next_steps(self, feedback: Dict, benchmarks: Dict, is_fundable: bool) -> Dict[str, Any]:
        """Generate next steps from AI feedback first, enhance with specifics"""
        
        # 1. Start with AI's action items if available
        ai_actions = feedback.get("action_items", [])
        ai_risks = feedback.get("key_risks", [])
        
        immediate = []
        thirty_days = []
        ninety_days = []
        
        # Use AI's actions as foundation
        for i, action in enumerate(ai_actions):
            if i < 2:
                immediate.append(action)
            elif i < 4:
                thirty_days.append(action)
            else:
                ninety_days.append(action)
        
        # Enhance with specific actions based on scores
        team_score = benchmarks.get("team_score", 5)
        product_score = benchmarks.get("product_score", 5)
        market_score = benchmarks.get("market_score", 5)
        
        # Add critical missing actions
        if team_score < 7 and not any("customer" in a.lower() for a in immediate):
            immediate.append("Schedule 20 customer discovery calls with target ICPs this week")
        
        if product_score < 7 and not any("mvp" in a.lower() or "prototype" in a.lower() for a in immediate):
            immediate.append("Ship MVP to 10 beta users with daily feedback loops")
        
        if not any("metric" in a.lower() or "analytic" in a.lower() for a in immediate):
            immediate.append("Implement product analytics and weekly KPI dashboard")
        
        # 30-day actions
        if not any("hire" in a.lower() or "recruit" in a.lower() for a in thirty_days):
            if team_score < 6:
                thirty_days.append("Hire senior go-to-market leader from target industry")
        
        if not any("customer" in a.lower() for a in thirty_days):
            thirty_days.append("Close first 10 paying customers at any price point")
        
        # 90-day actions
        if is_fundable and not any("raise" in a.lower() or "round" in a.lower() for a in ninety_days):
            ninety_days.append(f"Close ${2 + market_score/2:.0f}M seed round at ${10 + market_score}M pre-money")
        
        if not any("market fit" in a.lower() for a in ninety_days):
            ninety_days.append("Achieve product-market fit metrics: >40% weekly active, <5% monthly churn")
        
        # Ensure we have 5 actions for each timeframe
        self._fill_remaining_actions(immediate, thirty_days, ninety_days, benchmarks)
        
        return {
            "immediate": immediate[:5],
            "30_days": thirty_days[:5],
            "90_days": ninety_days[:5]
        }
    
    def _fill_remaining_actions(self, immediate: List, thirty_days: List, ninety_days: List, benchmarks: Dict):
        """Fill remaining slots with relevant actions"""
        
        # Immediate fillers
        immediate_fillers = [
            "Map competitive landscape with detailed feature/pricing matrix",
            "Set up CRM and customer support infrastructure",
            "Create pitch deck and one-pager for investors",
            "Launch landing page with waitlist capture",
            "Define ICP and create target account list"
        ]
        
        thirty_day_fillers = [
            "Build financial model with 18-month cash runway projection",
            "Establish customer advisory board with 3-5 target customers",
            "Launch content marketing with weekly blog/newsletter",
            "Implement SOC2 compliance roadmap for enterprise",
            "Create sales collateral and demo environment"
        ]
        
        ninety_day_fillers = [
            "Scale to 100+ active users with documented use cases",
            "Build partnerships with 3 channel partners or integrations",
            "Achieve positive unit economics in primary segment",
            "Expand team to 10 people across product/engineering/sales",
            "Launch in second market segment or geography"
        ]
        
        # Fill up to 5 items each
        while len(immediate) < 5 and immediate_fillers:
            action = immediate_fillers.pop(0)
            if action not in immediate:
                immediate.append(action)
        
        while len(thirty_days) < 5 and thirty_day_fillers:
            action = thirty_day_fillers.pop(0)
            if action not in thirty_days:
                thirty_days.append(action)
        
        while len(ninety_days) < 5 and ninety_day_fillers:
            action = ninety_day_fillers.pop(0)
            if action not in ninety_days:
                ninety_days.append(action)
    
    # Template fallbacks
    def _get_template_competitors(self, market_score: int) -> Dict[str, Any]:
        """Fallback template competitors when extraction fails"""
        if market_score >= 7:
            competitors = [
                {
                    "name": "Market Leader Inc",
                    "strength": "Dominant market position with strong network effects",
                    "weakness": "Legacy technology limiting innovation speed",
                    "market_share": "45%",
                    "funding": "$500M+ raised",
                    "key_differentiator": "First mover advantage and enterprise relationships",
                    "vulnerability": "Vulnerable to disruption from AI-native solutions",
                    "recent_moves": "Acquiring smaller competitors to maintain dominance"
                }
            ]
        else:
            competitors = [
                {
                    "name": "Established Player Corp",
                    "strength": "Solid product-market fit with steady growth",
                    "weakness": "Limited innovation budget",
                    "market_share": "30%",
                    "funding": "Well-funded",
                    "key_differentiator": "Trusted brand",
                    "vulnerability": "Slow to adapt to market changes",
                    "recent_moves": "Expanding internationally"
                }
            ]
        
        return {
            "main_competitors": competitors,
            "positioning": self._generate_positioning(market_score)
        }
    
    def _generate_positioning(self, market_score: int) -> str:
        """Generate positioning based on market score"""
        if market_score >= 7:
            return "Position as the next-generation solution with 10x better speed, price, and user experience"
        elif market_score >= 5:
            return "Focus on underserved segments where incumbents are weak"
        return "Find a defensible niche and build deep moats before expanding"
    
    def _get_template_tam(self, market_score: int) -> str:
        """Fallback TAM template"""
        if market_score >= 7:
            return f"${market_score * 2}B+ rapidly growing market"
        return f"${market_score}B market with moderate growth"
    
    def _get_target_segment(self) -> str:
        """Get target segment based on context"""
        context_segments = {
            'saas': "mid-market B2B companies",
            'fintech': "digital-first SMBs",
            'ai': "enterprise data teams",
            'marketplace': "long-tail suppliers",
            'healthcare': "specialty clinics",
            'tech': "growth-stage startups"
        }
        return context_segments.get(self.market_context, "target customer segment")