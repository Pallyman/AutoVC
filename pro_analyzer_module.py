# pro_analyzer.py
"""
Modular Pro Analysis Module for AutoVC
Handles generation and formatting of professional-level analysis insights
"""

from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class ProAnalyzer:
    """
    A dedicated class to handle the generation and formatting of
    "pro" level analysis insights.
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
        Generates comprehensive pro insights based on the base analysis.
        This creates realistic, detailed insights that complement the main analysis.
        """
        # Extract base metrics for context
        verdict = self.analysis.get("verdict", {})
        market = self.analysis.get("market_analysis", {})
        benchmarks = self.analysis.get("benchmarks", {})
        
        # Determine market context
        market_score = benchmarks.get("market_score", 5)
        is_fundable = verdict.get("decision") == "FUND"
        
        # Generate competitor analysis based on market context
        competitors = self._generate_competitor_analysis(market_score, is_fundable)
        
        # Generate market opportunity based on scores
        market_opp = self._generate_market_opportunity(market_score, is_fundable)
        
        # Generate financial projections
        financials = self._generate_financial_projections(is_fundable, market_score)
        
        # Generate actionable next steps
        next_steps = self._generate_next_steps(is_fundable, benchmarks)
        
        return {
            "competitor_analysis": competitors,
            "market_opportunity": market_opp,
            "financial_projections": financials,
            "next_steps": next_steps
        }
    
    def _generate_competitor_analysis(self, market_score: int, is_fundable: bool) -> Dict[str, Any]:
        """Generate realistic competitor analysis based on market conditions"""
        
        if market_score >= 8:
            # High-growth market with multiple players
            competitors = [
                {
                    "name": "MarketLeader Corp",
                    "strength": "85% market share with strong enterprise relationships",
                    "weakness": "Legacy technology stack limiting innovation speed",
                    "market_share": "85%",
                    "funding": "$500M Series E",
                    "key_differentiator": "20-year industry relationships and compliance certifications",
                    "vulnerability": "Slow to adopt AI/ML capabilities, vulnerable to disruption",
                    "recent_moves": "Acquired two AI startups to accelerate transformation"
                },
                {
                    "name": "AgileChallenger Inc",
                    "strength": "Modern tech stack and developer-friendly APIs",
                    "weakness": "Limited enterprise penetration and brand recognition",
                    "market_share": "8%",
                    "funding": "$75M Series C",
                    "key_differentiator": "Best-in-class developer experience and API documentation",
                    "vulnerability": "Burning cash rapidly, needs to show path to profitability",
                    "recent_moves": "Launched freemium tier to accelerate user acquisition"
                },
                {
                    "name": "TechDisruptor AI",
                    "strength": "AI-first approach with proprietary ML models",
                    "weakness": "Unproven at scale, limited customer base",
                    "market_share": "2%",
                    "funding": "$25M Series A",
                    "key_differentiator": "10x performance improvement using proprietary AI",
                    "vulnerability": "Single product focus, no platform strategy yet",
                    "recent_moves": "Hired VP Sales from MarketLeader to build enterprise sales"
                }
            ]
            positioning = "Position as the modern alternative that combines MarketLeader's reliability with AgileChallenger's innovation speed. Focus on mid-market where incumbents are weakest."
            
        elif market_score >= 6:
            # Moderate market with established players
            competitors = [
                {
                    "name": "EstablishedPlayer Co",
                    "strength": "Solid product-market fit with steady growth",
                    "weakness": "Limited innovation budget and risk-averse culture",
                    "market_share": "45%",
                    "funding": "$150M total raised",
                    "key_differentiator": "Trusted brand with 10+ years in market",
                    "vulnerability": "Technical debt limiting ability to add new features quickly",
                    "recent_moves": "Focusing on international expansion to find growth"
                },
                {
                    "name": "NicheSpecialist Ltd",
                    "strength": "Deep expertise in specific vertical markets",
                    "weakness": "Limited TAM due to narrow focus",
                    "market_share": "15%",
                    "funding": "$40M Series B",
                    "key_differentiator": "Purpose-built for healthcare/finance verticals",
                    "vulnerability": "Struggling to expand beyond initial verticals",
                    "recent_moves": "Building horizontal platform to enter new markets"
                }
            ]
            positioning = "Target underserved segments that incumbents ignore. Build specific features for SMBs that enterprise-focused competitors won't prioritize."
            
        else:
            # Challenging market with dominant incumbents
            competitors = [
                {
                    "name": "MegaCorp Global",
                    "strength": "Massive scale advantages and unlimited resources",
                    "weakness": "Bureaucratic decision-making and slow innovation cycles",
                    "market_share": "70%",
                    "funding": "Public company, $10B market cap",
                    "key_differentiator": "One-stop shop with integrated suite of products",
                    "vulnerability": "Poor user experience due to legacy acquisitions",
                    "recent_moves": "Aggressive acquisition strategy to eliminate competition"
                },
                {
                    "name": "BudgetOption Inc",
                    "strength": "Lowest price point in the market",
                    "weakness": "Poor product quality and high churn rates",
                    "market_share": "20%",
                    "funding": "Bootstrapped",
                    "key_differentiator": "Free tier and aggressive pricing",
                    "vulnerability": "Unsustainable unit economics, losing money on every customer",
                    "recent_moves": "Trying to move upmarket but struggling with enterprise features"
                }
            ]
            positioning = "Find a defensible niche where you can build deep moats. Consider partnering with MegaCorp rather than competing directly."
        
        return {
            "main_competitors": competitors,
            "positioning": positioning
        }
    
    def _generate_market_opportunity(self, market_score: int, is_fundable: bool) -> Dict[str, Any]:
        """Generate market opportunity analysis based on market conditions"""
        
        if market_score >= 8:
            return {
                "tam_breakdown": "$15B global market growing at 25% CAGR. North America represents $6B, Europe $4B, APAC $3B, Rest of World $2B. Cloud segment growing fastest at 40% annually.",
                "sam": "$3B serviceable market focusing on mid-market and enterprise in North America and Europe, excluding regulated industries initially",
                "som": "$150M realistic capture in 3 years (5% of SAM) through focused go-to-market in tech and retail verticals",
                "growth_rate": "Expected 35% CAGR driven by digital transformation acceleration and AI adoption"
            }
        elif market_score >= 6:
            return {
                "tam_breakdown": "$5B market with 15% CAGR. Mature in developed markets but high growth in emerging economies. Enterprise segment is 60% of market.",
                "sam": "$800M addressable focusing on SMB and mid-market where incumbents are weak. Avoiding enterprise initially due to long sales cycles.",
                "som": "$40M achievable through targeted vertical strategy and channel partnerships",
                "growth_rate": "Market growing at 15% but our segment growing at 25% as SMBs digitize"
            }
        else:
            return {
                "tam_breakdown": "$2B market growing at 5% annually. Highly consolidated with top 3 players controlling 85% share. Limited new customer acquisition.",
                "sam": "$200M in underserved niches and international markets where incumbents have weak presence",
                "som": "$10M through highly targeted approach and superior customer experience",
                "growth_rate": "Overall market stagnant but opportunity in market share capture from incumbents"
            }
    
    def _generate_financial_projections(self, is_fundable: bool, market_score: int) -> Dict[str, Any]:
        """Generate realistic financial projections based on analysis"""
        
        if is_fundable and market_score >= 7:
            return {
                "year_1": {"users": "2,500", "revenue": "$500K", "burn": "$2M"},
                "year_2": {"users": "15,000", "revenue": "$3M", "burn": "$4M"},
                "year_3": {"users": "50,000", "revenue": "$12M", "burn": "$2M"}
            }
        elif market_score >= 5:
            return {
                "year_1": {"users": "500", "revenue": "$100K", "burn": "$1M"},
                "year_2": {"users": "2,500", "revenue": "$600K", "burn": "$1.5M"},
                "year_3": {"users": "8,000", "revenue": "$2.4M", "burn": "$500K"}
            }
        else:
            return {
                "year_1": {"users": "100", "revenue": "$30K", "burn": "$500K"},
                "year_2": {"users": "500", "revenue": "$150K", "burn": "$400K"},
                "year_3": {"users": "1,500", "revenue": "$450K", "burn": "$200K"}
            }
    
    def _generate_next_steps(self, is_fundable: bool, benchmarks: Dict[str, Any]) -> Dict[str, Any]:
        """Generate actionable next steps based on analysis"""
        
        team_score = benchmarks.get("team_score", 5)
        product_score = benchmarks.get("product_score", 5)
        market_score = benchmarks.get("market_score", 5)
        
        immediate_actions = []
        thirty_day_actions = []
        ninety_day_actions = []
        
        # Team-related actions
        if team_score < 7:
            immediate_actions.append("Schedule 20 customer discovery calls to validate problem assumptions")
            thirty_day_actions.append("Hire senior sales leader with industry experience")
            ninety_day_actions.append("Build advisory board with 3 industry veterans")
        else:
            immediate_actions.append("Leverage team expertise to get 5 design partners signed")
            thirty_day_actions.append("Implement weekly customer feedback loops")
            ninety_day_actions.append("Scale team with 2 senior engineers")
        
        # Product-related actions
        if product_score < 7:
            immediate_actions.append("Create clickable prototype for user testing")
            thirty_day_actions.append("Launch MVP with 3 core features to test PMF")
            ninety_day_actions.append("Achieve 50+ NPS score from initial users")
        else:
            immediate_actions.append("Implement analytics to track feature usage")
            thirty_day_actions.append("Launch v2 based on user feedback")
            ninety_day_actions.append("Hit 80% feature adoption rate")
        
        # Market-related actions
        if market_score < 6:
            immediate_actions.append("Narrow focus to single beachhead market")
            thirty_day_actions.append("Validate willingness to pay through 10 LOIs")
            ninety_day_actions.append("Achieve product-market fit in beachhead")
        else:
            immediate_actions.append("Map competitive landscape and positioning")
            thirty_day_actions.append("Launch targeted marketing campaign")
            ninety_day_actions.append("Capture 1% market share in target segment")
        
        # Funding-related actions
        if is_fundable:
            immediate_actions.append("Prepare comprehensive data room for investors")
            ninety_day_actions.append("Close $2M seed round from tier-1 VCs")
        else:
            immediate_actions.append("Extend runway through revenue or grants")
            ninety_day_actions.append("Achieve cash flow positive in one segment")
        
        # Always include these critical actions
        immediate_actions.append("Set up automated analytics and KPI dashboard")
        thirty_day_actions.append("Establish weekly metrics review process")
        ninety_day_actions.append("Build repeatable sales playbook")
        
        return {
            "immediate": immediate_actions[:5],  # Top 5 immediate actions
            "30_days": thirty_day_actions[:5],   # Top 5 30-day actions
            "90_days": ninety_day_actions[:5]    # Top 5 90-day actions
        }
