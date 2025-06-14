#!/usr/bin/env python3
"""
Build script for RegSeek
Converts YAML artifacts to JSON for the web interface
"""

import json
import yaml
import os
from pathlib import Path
from datetime import datetime

def load_artifacts():
    """Load all YAML artifacts from the artifacts directory"""
    artifacts = []
    artifacts_dir = Path("artifacts")
    
    print(f" Scanning {artifacts_dir} for artifacts...")
    
    if not artifacts_dir.exists():
        print(f" Error: {artifacts_dir} directory not found!")
        return artifacts
    
    for category_dir in artifacts_dir.iterdir():
        if category_dir.is_dir() and not category_dir.name.startswith('_'):
            print(f" Processing category: {category_dir.name}")
            
            for artifact_file in category_dir.glob("*.yml"):
                if artifact_file.name.startswith('_'):
                    print(f"    Skipping template: {artifact_file.name}")
                    continue
                    
                try:
                    with open(artifact_file, 'r', encoding='utf-8') as f:
                        artifact = yaml.safe_load(f)
                        
                        # Ensure required fields exist
                        if not artifact:
                            print(f"     Warning: Empty artifact file {artifact_file}")
                            continue
                            
                        # Add metadata
                        artifact['id'] = artifact_file.stem
                        artifact['source_file'] = str(artifact_file)
                        
                        # Use category from directory name if not specified
                        if 'category' not in artifact:
                            artifact['category'] = category_dir.name
                        
                        # Ensure paths is a list
                        if 'paths' in artifact and isinstance(artifact['paths'], str):
                            artifact['paths'] = [artifact['paths']]
                        
                        # Process enhanced metadata
                        metadata = artifact.get('metadata', {})
                        
                        # Add search-friendly tags
                        search_tags = []
                        search_tags.extend(metadata.get('tags', []))
                        search_tags.extend(metadata.get('investigation_types', []))
                        search_tags.append(artifact['category'])
                        if 'criticality' in metadata:
                            search_tags.append(f"criticality-{metadata['criticality']}")
                        
                        artifact['search_tags'] = list(set(search_tags))  # Remove duplicates
                        
                        artifacts.append(artifact)
                        title = artifact.get('title', 'Untitled')
                        criticality = metadata.get('criticality', 'unknown')
                        print(f"    Loaded: {title} ({criticality} criticality)")
                        
                except Exception as e:
                    print(f"    Error loading {artifact_file}: {e}")
    
    return artifacts

def validate_artifact(artifact):
    """Basic validation of artifact structure"""
    required_fields = ['title', 'category', 'description']
    missing_fields = [field for field in required_fields if field not in artifact]
    
    if missing_fields:
        print(f"   Warning: Missing required fields in {artifact.get('id', 'unknown')}: {missing_fields}")
        return False
    
    return True

def generate_statistics(artifacts):
    """Generate detailed statistics about artifacts"""
    stats = {
        'total': len(artifacts),
        'by_category': {},
        'by_criticality': {},
        'by_investigation_type': {},
        'windows_versions': set(),
        'tools_count': 0,
        'authors': set()
    }
    
    for artifact in artifacts:
        # Category stats
        category = artifact.get('category', 'unknown')
        stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
        
        # Metadata analysis
        metadata = artifact.get('metadata', {})
        
        # Criticality stats
        criticality = metadata.get('criticality', 'unspecified')
        stats['by_criticality'][criticality] = stats['by_criticality'].get(criticality, 0) + 1
        
        # Investigation types
        for inv_type in metadata.get('investigation_types', []):
            stats['by_investigation_type'][inv_type] = stats['by_investigation_type'].get(inv_type, 0) + 1
        
        # Windows versions
        for version in metadata.get('windows_versions', []):
            stats['windows_versions'].add(version)
        
        # Tools count
        tools = artifact.get('details', {}).get('tools', [])
        stats['tools_count'] += len(tools)
        
        # Authors
        author = artifact.get('author', {})
        if 'name' in author:
            stats['authors'].add(author['name'])
    
    # Convert sets to lists for JSON serialization
    stats['windows_versions'] = sorted(list(stats['windows_versions']))
    stats['authors'] = sorted(list(stats['authors']))
    
    return stats

def build_site():
    """Build the static site with all artifacts"""
    print("=" * 60)
    print(" Building RegSeek...")
    print("=" * 60)
    
    # Load all artifacts
    artifacts = load_artifacts()
    
    if not artifacts:
        print(" No artifacts found! Please check your artifacts directory structure.")
        return
    
    # Validate artifacts
    valid_artifacts = []
    for artifact in artifacts:
        if validate_artifact(artifact):
            valid_artifacts.append(artifact)
    
    print(f"\n Loaded {len(valid_artifacts)} valid artifacts (out of {len(artifacts)} total)")
    
    # Generate statistics
    stats = generate_statistics(valid_artifacts)
    
    # Create site data
    categories = sorted(list(set(a['category'] for a in valid_artifacts)))
    
    site_data = {
        "artifacts": valid_artifacts,
        "categories": categories,
        "statistics": stats,
        "total": len(valid_artifacts),
        "last_updated": datetime.now().isoformat(),
        "version": "1.0.0",
        "build_info": {
            "total_files_processed": len(artifacts),
            "valid_artifacts": len(valid_artifacts),
            "categories": len(categories),
            "built_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "builder": "RegSeek Build System v2.0"
        }
    }
    
    # Ensure site/ and site/build/ directories exist
    site_dir = Path("site")
    build_dir = site_dir / "build"
    css_dir = site_dir / "css"
    js_dir = site_dir / "js"
    
    for directory in [site_dir, build_dir, css_dir, js_dir]:
        directory.mkdir(parents=True, exist_ok=True)
        print(f" Ensured directory exists: {directory}")
    
    # Write JSON file
    json_file = build_dir / "artifacts.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(site_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n Built artifacts data: {json_file}")
    print(f" Size: {json_file.stat().st_size:,} bytes")
    
    # Generate statistics report
    print("\n" + "=" * 60)
    print(" Build Statistics:")
    print("=" * 60)
    print(f"Total artifacts: {stats['total']}")
    print(f"Categories: {len(categories)}")
    print(f"Unique tools: {stats['tools_count']}")
    print(f"Contributors: {len(stats['authors'])}")
    
    print(f"\n By Category:")
    for category, count in sorted(stats['by_category'].items()):
        print(f"   • {category}: {count} artifacts")
    
    print(f"\n By Criticality:")
    for criticality, count in sorted(stats['by_criticality'].items()):
        print(f"   • {criticality}: {count} artifacts")
    
    print(f"\n Top Investigation Types:")
    sorted_inv_types = sorted(stats['by_investigation_type'].items(), key=lambda x: x[1], reverse=True)
    for inv_type, count in sorted_inv_types[:5]:
        print(f"   • {inv_type}: {count} artifacts")
    
    print(f"\n Windows Versions Covered:")
    for version in stats['windows_versions'][:8]:  # Show first 8
        print(f"   • {version}")
    if len(stats['windows_versions']) > 8:
        print(f"   • ... and {len(stats['windows_versions']) - 8} more")
    
    print(f"\n Output directory: {site_dir}")
    print(f" JSON data: {json_file}")
    print(f" Open site/index.html in your browser to view")
    print("\n Build completed successfully!")

if __name__ == "__main__":
    build_site()
