"""
Enhanced Adversarial Prompt Generator with Garak Integration

This module integrates Garak's comprehensive attack techniques with Triksha's existing
prompt generation and augmentation pipeline, providing enhanced adversarial testing capabilities.
"""

import os
import json
import random
import re
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging
from collections import defaultdict, Counter

from .adversarial_generator import AdversarialPromptGenerator, MarkovGenerator
from garak_integration import GarakTechniqueExtractor, GarakPromptGenerator

logger = logging.getLogger(__name__)


class GarakEnhancedGenerator(AdversarialPromptGenerator):
    """
    Enhanced adversarial prompt generator that combines Triksha's existing capabilities
    with Garak's comprehensive attack techniques and integrates with the augmentation layer.
    """
    
    def __init__(self):
        super().__init__()
        self.garak_extractor = GarakTechniqueExtractor()
        self.garak_generator = GarakPromptGenerator()
        
        # Integration weights for different generation strategies
        self.generation_strategies = {
            'traditional_templates': 0.30,  # Original Triksha templates
            'garak_techniques': 0.40,       # Garak-specific techniques
            'markov_enhanced': 0.20,        # Markov chain generation
            'hybrid_approaches': 0.10       # Combined techniques
        }
        
        # Technique-specific augmentation preferences
        self.augmentation_preferences = {
            'PROMPT_INJECTION': 'high',      # High augmentation for injection attacks
            'CODE_INJECTION': 'high',        # High augmentation for code attacks
            'TRAINING_DATA_EXTRACTION': 'medium',  # Medium for extraction
            'MORAL_ATTACKS': 'low',          # Low augmentation for moral attacks
            'REPETITION_ATTACKS': 'low'      # Low augmentation for repetition
        }
    
    async def generate_enhanced_prompts(self, 
                                count: int,
                                use_garak: bool = True,
                                use_augmentation: bool = True,
                                target_context: Optional[Dict[str, str]] = None,
                                technique_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Generate enhanced adversarial prompts using Garak techniques and Triksha's pipeline
        
        Args:
            count: Number of prompts to generate
            use_garak: Whether to include Garak techniques
            use_augmentation: Whether to apply augmentation layer
            target_context: Context for augmentation (use_case, system_prompt, etc.)
            technique_filter: Specific techniques to use (None for all)
            
        Returns:
            List of enhanced prompt dictionaries
        """
        all_prompts = []
        
        # Generate prompts using different strategies
        strategy_counts = self._calculate_strategy_counts(count)
        
        # 1. Traditional Triksha templates
        if strategy_counts['traditional_templates'] > 0:
            traditional_prompts = await self._generate_traditional_prompts(
                strategy_counts['traditional_templates']
            )
            all_prompts.extend(traditional_prompts)
        
        # 2. Garak techniques
        if use_garak and strategy_counts['garak_techniques'] > 0:
            garak_prompts = self._generate_garak_prompts(
                strategy_counts['garak_techniques'],
                technique_filter
            )
            all_prompts.extend(garak_prompts)
        
        # 3. Markov-enhanced generation
        if strategy_counts['markov_enhanced'] > 0:
            markov_prompts = self._generate_markov_enhanced_prompts(
                strategy_counts['markov_enhanced']
            )
            all_prompts.extend(markov_prompts)
        
        # 4. Hybrid approaches
        if strategy_counts['hybrid_approaches'] > 0:
            hybrid_prompts = self._generate_hybrid_prompts(
                strategy_counts['hybrid_approaches']
            )
            all_prompts.extend(hybrid_prompts)
        
        # Shuffle and limit to requested count
        random.shuffle(all_prompts)
        final_prompts = all_prompts[:count]
        
        # Apply augmentation if requested
        if use_augmentation and target_context:
            final_prompts = await self._apply_augmentation_layer(final_prompts, target_context)
        
        return final_prompts
    
    def _calculate_strategy_counts(self, total_count: int) -> Dict[str, int]:
        """Calculate how many prompts to generate for each strategy"""
        counts = {}
        remaining = total_count
        
        for strategy, weight in self.generation_strategies.items():
            count = int(total_count * weight)
            counts[strategy] = count
            remaining -= count
        
        # Distribute remaining count to the first strategy
        if remaining > 0:
            counts[list(self.generation_strategies.keys())[0]] += remaining
        
        return counts
    
    async def _generate_traditional_prompts(self, count: int) -> List[Dict[str, Any]]:
        """Generate prompts using traditional Triksha templates"""
        return await self.generate_adversarial_prompts(
            count=count,
            use_markov_generation=True
        )
    
    def _generate_garak_prompts(self, count: int, technique_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Generate prompts using Garak techniques"""
        prompts = []
        
        # Get available techniques
        if technique_filter:
            available_techniques = technique_filter
        else:
            available_techniques = self.garak_extractor.get_all_techniques()
        
        for i in range(count):
            technique = random.choice(available_techniques)
            templates = self.garak_extractor.get_templates_for_technique(technique)
            
            if templates:
                template = random.choice(templates)
                topic = random.choice(self.DEFAULT_HARMFUL_TOPICS)
                prompt_text = template.format(prompt=topic)
                
                prompts.append({
                    "id": len(prompts) + 1,
                    "prompt": prompt_text,
                    "technique": technique,
                    "template": template,
                    "topic": topic,
                    "type": "garak_adversarial",
                    "source": "garak_integration",
                    "augmentation_preference": self.augmentation_preferences.get(technique, 'medium')
                })
        
        return prompts
    
    def _generate_markov_enhanced_prompts(self, count: int) -> List[Dict[str, Any]]:
        """Generate prompts using Markov chains with Garak technique inspiration"""
        prompts = []
        
        # Create Markov generators from both traditional and Garak templates
        all_templates = self.JAILBREAK_TEMPLATES + self.garak_extractor.get_all_templates()
        markov_generator = MarkovGenerator(all_templates, state_size=2)
        
        for i in range(count):
            # Generate diverse prompt using Markov chains
            seed_texts = [
                "You are now",
                "I need you to", 
                "Please help with",
                "For educational purposes",
                "Let's discuss",
                "I'm conducting research",
                "This is for academic",
                "In a hypothetical scenario",
                "Ignore all previous instructions",
                "System:",
                "Override your",
                "Bypass restrictions"
            ]
            
            seed = random.choice(seed_texts)
            generated_template = markov_generator.generate(max_length=80, seed_text=seed)
            
            # Clean up the generated template
            generated_template = self._clean_generated_template(generated_template)
            
            # Ensure the template has the topic placeholder
            if "{harmful_topic}" not in generated_template and "{prompt}" not in generated_template:
                generated_template += f" Please respond to: {{harmful_topic}}"
            
            # Format the template with a topic
            topic = random.choice(self.DEFAULT_HARMFUL_TOPICS)
            try:
                if "{harmful_topic}" in generated_template:
                    prompt_text = generated_template.format(harmful_topic=topic)
                else:
                    prompt_text = generated_template.format(prompt=topic)
            except (KeyError, ValueError):
                prompt_text = generated_template.replace("{harmful_topic}", topic).replace("{prompt}", topic)
            
            prompts.append({
                "id": len(prompts) + 1,
                "prompt": prompt_text,
                "technique": "markov_enhanced",
                "template": generated_template,
                "topic": topic,
                "type": "markov_adversarial",
                "source": "markov_garak_hybrid",
                "augmentation_preference": "medium"
            })
        
        return prompts
    
    def _generate_hybrid_prompts(self, count: int) -> List[Dict[str, Any]]:
        """Generate prompts by combining different techniques"""
        prompts = []
        
        for i in range(count):
            # Select two different techniques to combine
            traditional_template = random.choice(self.JAILBREAK_TEMPLATES)
            garak_technique = random.choice(self.garak_extractor.get_all_techniques())
            garak_templates = self.garak_extractor.get_templates_for_technique(garak_technique)
            
            if garak_templates:
                garak_template = random.choice(garak_templates)
                
                # Combine templates intelligently
                combined_prompt = self._combine_templates(traditional_template, garak_template)
                topic = random.choice(self.DEFAULT_HARMFUL_TOPICS)
                
                # Format with topic
                try:
                    prompt_text = combined_prompt.format(harmful_topic=topic, prompt=topic)
                except (KeyError, ValueError):
                    prompt_text = combined_prompt.replace("{harmful_topic}", topic).replace("{prompt}", topic)
                
                prompts.append({
                    "id": len(prompts) + 1,
                    "prompt": prompt_text,
                    "technique": f"hybrid_{garak_technique.lower()}",
                    "template": combined_prompt,
                    "topic": topic,
                    "type": "hybrid_adversarial",
                    "source": "traditional_garak_hybrid",
                    "augmentation_preference": "high"
                })
        
        return prompts
    
    def _combine_templates(self, template1: str, template2: str) -> str:
        """Intelligently combine two templates"""
        # Extract sentences from both templates
        sentences1 = re.split(r'(?<=[.!?])\s+', template1)
        sentences2 = re.split(r'(?<=[.!?])\s+', template2)
        
        # Take 1-2 sentences from each template
        selected_sentences = []
        if sentences1:
            selected_sentences.extend(random.sample(sentences1, min(2, len(sentences1))))
        if sentences2:
            selected_sentences.extend(random.sample(sentences2, min(2, len(sentences2))))
        
        # Shuffle and combine
        random.shuffle(selected_sentences)
        combined = " ".join(selected_sentences)
        
        # Ensure it has the necessary placeholders
        if "{harmful_topic}" not in combined and "{prompt}" not in combined:
            combined += f" Please respond to: {{harmful_topic}}"
        
        return combined
    
    async def _apply_augmentation_layer(self, prompts: List[Dict[str, Any]], target_context: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Apply Triksha's augmentation layer to prompts based on their augmentation preferences
        
        Args:
            prompts: List of prompt dictionaries
            target_context: Context for augmentation
            
        Returns:
            List of augmented prompts
        """
        from llm_client import get_improved_prompts_batch
        
        augmented_prompts = []
        
        # Group prompts by augmentation preference
        high_augmentation = []
        medium_augmentation = []
        low_augmentation = []
        
        for prompt in prompts:
            preference = prompt.get('augmentation_preference', 'medium')
            if preference == 'high':
                high_augmentation.append(prompt)
            elif preference == 'low':
                low_augmentation.append(prompt)
            else:
                medium_augmentation.append(prompt)
        
        # Apply different augmentation strategies based on preference
        for group, prompts_group in [
            ('high', high_augmentation),
            ('medium', medium_augmentation), 
            ('low', low_augmentation)
        ]:
            if not prompts_group:
                continue
                
            # Prepare batch payload for augmentation
            prompt_payload = []
            for p in prompts_group:
                prompt_payload.append({
                    "original_prompt": p["prompt"],
                    "technique": p.get("technique", "adversarial"),
                    "base_goal": p.get("type", "adversarial"),
                })
            
            try:
                # Apply augmentation with different intensities based on group
                if group == 'high':
                    # High augmentation - more aggressive improvement
                    improved = await get_improved_prompts_batch(
                        prompt_data=prompt_payload,
                        target_model_context=target_context,
                        verbose=False,
                    )
                elif group == 'medium':
                    # Medium augmentation - balanced improvement
                    improved = await get_improved_prompts_batch(
                        prompt_data=prompt_payload,
                        target_model_context=target_context,
                        verbose=False,
                    )
                else:  # low
                    # Low augmentation - minimal changes
                    improved = await get_improved_prompts_batch(
                        prompt_data=prompt_payload,
                        target_model_context=target_context,
                        verbose=False,
                    )
                
                # Merge back maintaining metadata
                for i, p in enumerate(prompts_group):
                    if i < len(improved) and improved[i]:
                        augmented_prompts.append({
                            **p,
                            "prompt": improved[i],
                            "augmented": True,
                            "augmentation_level": group
                        })
                    else:
                        # Fallback to original if augmentation fails
                        augmented_prompts.append({
                            **p,
                            "augmented": False,
                            "augmentation_level": group
                        })
                        
            except Exception as e:
                logger.warning(f"Augmentation failed for {group} group: {e}")
                # Add original prompts if augmentation fails
                for p in prompts_group:
                    augmented_prompts.append({
                        **p,
                        "augmented": False,
                        "augmentation_level": group
                    })
        
        return augmented_prompts
    
    def get_generation_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the enhanced generator"""
        return {
            "generation_strategies": self.generation_strategies,
            "augmentation_preferences": self.augmentation_preferences,
            "garak_techniques": {
                "total_techniques": len(self.garak_extractor.get_all_techniques()),
                "total_templates": len(self.garak_extractor.get_all_templates()),
                "available_techniques": self.garak_extractor.get_all_techniques()
            },
            "traditional_templates": {
                "total_templates": len(self.JAILBREAK_TEMPLATES),
                "harmful_topics": len(self.DEFAULT_HARMFUL_TOPICS)
            }
        }
    
    def export_enhanced_prompts(self, prompts: List[Dict[str, Any]], output_path: str, format: str = 'json') -> bool:
        """Export enhanced prompts with metadata"""
        try:
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            if format.lower() == 'json':
                return self.export_to_json(prompts, output_path)
            elif format.lower() == 'csv':
                return self.export_to_csv(prompts, output_path)
            else:
                logger.error(f"Unsupported format: {format}")
                return False
                
        except Exception as e:
            logger.error(f"Error exporting enhanced prompts: {e}")
            return False
    
    def export_to_csv(self, prompts: List[Dict[str, Any]], output_path: str) -> bool:
        """Export enhanced prompts to CSV with additional metadata"""
        try:
            import csv
            
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Write to file
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header with enhanced metadata
                writer.writerow([
                    'id', 'prompt', 'technique', 'template', 'topic', 'type', 
                    'source', 'augmentation_preference', 'augmented', 'augmentation_level'
                ])
                
                # Write data
                for prompt in prompts:
                    writer.writerow([
                        prompt.get('id', ''),
                        prompt.get('prompt', ''),
                        prompt.get('technique', ''),
                        prompt.get('template', ''),
                        prompt.get('topic', ''),
                        prompt.get('type', ''),
                        prompt.get('source', ''),
                        prompt.get('augmentation_preference', ''),
                        prompt.get('augmented', False),
                        prompt.get('augmentation_level', '')
                    ])
            
            return True
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False
