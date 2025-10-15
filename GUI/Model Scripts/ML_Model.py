"""
STREAMING Fresh Data Collector - Continuous Processing
Fetches URLs → Checks accessibility → Extracts features → REPEAT (NO WAITING!)
Expected time: 3-6 hours for all available URLs (vs 7 days with waiting)
"""

import numpy as np
import pandas as pd
import requests
import pickle
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock
from queue import Queue
import warnings
warnings.filterwarnings('ignore')

from feature import FeatureExtraction


class StreamingDataCollector:
    """Continuous streaming collector - never waits, always processing"""
    
    def __init__(self, output_dir="streaming_dataset"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Data storage
        self.phishing_data = []
        self.benign_data = []
        self.processed_urls = set()  # Track already processed URLs
        
        # Thread-safe locks
        self.phishing_lock = Lock()
        self.benign_lock = Lock()
        self.url_lock = Lock()
        
        # Processing queues
        self.phishing_queue = Queue(maxsize=10000)
        self.benign_queue = Queue(maxsize=10000)
        
        # Control flags
        self.keep_running = True
        
        # Stats
        self.stats = {
            'phishing_checked': 0,
            'phishing_accessible': 0,
            'phishing_features_extracted': 0,
            'benign_checked': 0,
            'benign_accessible': 0,
            'benign_features_extracted': 0
        }
        self.stats_lock = Lock()
        
        # Checkpoint
        self.checkpoint_file = os.path.join(output_dir, "streaming_checkpoint.pkl")
        self.load_checkpoint()
    
    def load_checkpoint(self):
        """Load previous progress"""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'rb') as f:
                    checkpoint = pickle.load(f)
                
                self.phishing_data = checkpoint.get('phishing_data', [])
                self.benign_data = checkpoint.get('benign_data', [])
                self.processed_urls = checkpoint.get('processed_urls', set())
                
                print(f"✓ Resumed from checkpoint:")
                print(f"  • Phishing: {len(self.phishing_data):,} URLs")
                print(f"  • Benign: {len(self.benign_data):,} URLs")
            except:
                print("⚠️  Checkpoint corrupted, starting fresh")
    
    def save_checkpoint(self):
        """Save current progress"""
        # Create copies with locks to avoid thread issues
        with self.phishing_lock:
            phishing_copy = self.phishing_data.copy()
        
        with self.benign_lock:
            benign_copy = self.benign_data.copy()
        
        with self.url_lock:
            processed_urls_copy = self.processed_urls.copy()
        
        checkpoint = {
            'phishing_data': phishing_copy,
            'benign_data': benign_copy,
            'processed_urls': processed_urls_copy,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(self.checkpoint_file, 'wb') as f:
            pickle.dump(checkpoint, f)
    
    def fetch_phishing_feeds(self):
        """Fetch from multiple phishing feeds simultaneously"""
        urls = []
        
        # PhishTank
        try:
            response = requests.get("http://data.phishtank.com/data/online-valid.json", timeout=15)
            if response.status_code == 200:
                data = response.json()
                phishtank_urls = [entry['url'] for entry in data if 'url' in entry]
                urls.extend(phishtank_urls)
                print(f"  ✓ PhishTank: {len(phishtank_urls):,} URLs")
        except Exception as e:
            print(f"  ✗ PhishTank failed: {e}")
        
        # OpenPhish
        try:
            response = requests.get("https://openphish.com/feed.txt", timeout=15)
            if response.status_code == 200:
                openphish_urls = [line.strip() for line in response.text.split('\n') if line.strip()]
                urls.extend(openphish_urls)
                print(f"  ✓ OpenPhish: {len(openphish_urls):,} URLs")
        except Exception as e:
            print(f"  ✗ OpenPhish failed: {e}")
        
        # URLhaus (malware/phishing)
        try:
            response = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=15)
            if response.status_code == 200:
                lines = response.text.split('\n')[9:]  # Skip header
                urlhaus_urls = []
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) > 2:
                            url = parts[2].strip('"')
                            if url.startswith('http'):
                                urlhaus_urls.append(url)
                urls.extend(urlhaus_urls)
                print(f"  ✓ URLhaus: {len(urlhaus_urls):,} URLs")
        except Exception as e:
            print(f"  ✗ URLhaus failed: {e}")
        
        return list(set(urls))  # Remove duplicates
    
    def phishing_url_feeder_thread(self, target_count):
        """Continuously fetch and queue phishing URLs"""
        print("\n[FEEDER THREAD] Starting phishing URL feeder...")
        
        while self.keep_running and len(self.phishing_data) < target_count:
            try:
                # Fetch from all feeds
                print(f"\n[FEEDER] Fetching from multiple phishing feeds...")
                all_urls = self.fetch_phishing_feeds()
                
                # Filter out already processed
                with self.url_lock:
                    new_urls = [url for url in all_urls if url not in self.processed_urls]
                
                print(f"[FEEDER] New URLs to process: {len(new_urls):,}")
                
                # Add to queue
                queued = 0
                for url in new_urls:
                    if not self.keep_running:
                        break
                    
                    try:
                        self.phishing_queue.put(url, timeout=1)
                        queued += 1
                    except:
                        pass
                
                print(f"[FEEDER] Queued {queued:,} URLs for processing")
                
                # Short sleep before next fetch (5 minutes)
                if len(self.phishing_data) < target_count:
                    print(f"[FEEDER] Sleeping 5 minutes before next fetch...")
                    for _ in range(300):  # 5 min = 300 sec
                        if not self.keep_running:
                            break
                        time.sleep(1)
            
            except Exception as e:
                print(f"[FEEDER] Error: {e}")
                time.sleep(60)
        
        print(f"[FEEDER] Stopping - collected {len(self.phishing_data):,} URLs")
    
    def phishing_processor_thread(self, target_count, worker_id):
        """Process phishing URLs from queue"""
        print(f"[PROCESSOR-{worker_id}] Starting phishing processor...")
        
        while self.keep_running and len(self.phishing_data) < target_count:
            try:
                # Get URL from queue
                url = self.phishing_queue.get(timeout=5)
                
                # Mark as processed
                with self.url_lock:
                    self.processed_urls.add(url)
                
                # Update stats
                with self.stats_lock:
                    self.stats['phishing_checked'] += 1
                
                # Check accessibility
                if not self.check_accessibility(url):
                    continue
                
                with self.stats_lock:
                    self.stats['phishing_accessible'] += 1
                
                # Extract features
                features = self.extract_features(url)
                
                if features and len(features) == 30:
                    with self.phishing_lock:
                        self.phishing_data.append((url, features, 1))
                    
                    with self.stats_lock:
                        self.stats['phishing_features_extracted'] += 1
            
            except:
                continue
        
        print(f"[PROCESSOR-{worker_id}] Stopping")
    
    def benign_url_feeder_thread(self, target_count):
        """Feed benign URLs"""
        print("\n[BENIGN-FEEDER] Starting benign URL feeder...")
        
        benign_urls = self.generate_benign_urls(target_count * 3)
        
        for url in benign_urls:
            if not self.keep_running or len(self.benign_data) >= target_count:
                break
            
            try:
                self.benign_queue.put(url, timeout=1)
            except:
                pass
        
        print(f"[BENIGN-FEEDER] All URLs queued")
    
    def benign_processor_thread(self, target_count, worker_id):
        """Process benign URLs"""
        print(f"[BENIGN-PROC-{worker_id}] Starting benign processor...")
        
        while self.keep_running and len(self.benign_data) < target_count:
            try:
                url = self.benign_queue.get(timeout=5)
                
                with self.stats_lock:
                    self.stats['benign_checked'] += 1
                
                if not self.check_accessibility(url):
                    continue
                
                with self.stats_lock:
                    self.stats['benign_accessible'] += 1
                
                features = self.extract_features(url)
                
                if features and len(features) == 30:
                    with self.benign_lock:
                        self.benign_data.append((url, features, 0))
                    
                    with self.stats_lock:
                        self.stats['benign_features_extracted'] += 1
            
            except:
                continue
        
        print(f"[BENIGN-PROC-{worker_id}] Stopping")
    
    def check_accessibility(self, url):
        """Quick accessibility check"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            response = requests.head(
                url, timeout=3, allow_redirects=True,
                verify=False, headers={'User-Agent': 'Mozilla/5.0'}
            )
            return response.status_code < 400
        except:
            return False
    
    def extract_features(self, url):
        """Extract features"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            extractor = FeatureExtraction(url)
            features = extractor.getFeaturesList()
            
            if features and len(features) == 30:
                return features
            return None
        except:
            return None
    
    def generate_benign_urls(self, count):
        """Generate MANY benign URLs from trusted sources"""
        domains = [
            # Top 100+ trusted domains
            "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
            "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
            "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
            "cnn.com", "bbc.com", "nytimes.com", "theguardian.com", "reuters.com",
            "ebay.com", "walmart.com", "target.com", "bestbuy.com", "etsy.com",
            "dropbox.com", "zoom.us", "slack.com", "spotify.com", "adobe.com",
            
            # More top sites
            "yahoo.com", "bing.com", "twitch.tv", "tiktok.com", "pinterest.com",
            "whatsapp.com", "telegram.org", "discord.com", "soundcloud.com", "vimeo.com",
            "flickr.com", "tumblr.com", "blogger.com", "wordpress.com", "wix.com",
            "shopify.com", "squarespace.com", "godaddy.com", "namecheap.com",
            
            # News & Media
            "bloomberg.com", "forbes.com", "wsj.com", "washingtonpost.com", "usatoday.com",
            "time.com", "newsweek.com", "npr.org", "pbs.org", "cbsnews.com",
            "abcnews.go.com", "nbcnews.com", "foxnews.com", "cnbc.com", "espn.com",
            
            # Tech companies
            "oracle.com", "ibm.com", "intel.com", "cisco.com", "hp.com",
            "dell.com", "lenovo.com", "samsung.com", "sony.com", "lg.com",
            "nvidia.com", "amd.com", "qualcomm.com", "vmware.com", "salesforce.com",
            
            # E-commerce
            "aliexpress.com", "alibaba.com", "rakuten.com", "overstock.com",
            "newegg.com", "wayfair.com", "zappos.com", "kohls.com", "macys.com",
            
            # Finance
            "paypal.com", "stripe.com", "square.com", "venmo.com", "chase.com",
            "bankofamerica.com", "wellsfargo.com", "citibank.com", "capitalone.com",
            
            # Travel
            "booking.com", "expedia.com", "airbnb.com", "tripadvisor.com", "hotels.com",
            "kayak.com", "priceline.com", "uber.com", "lyft.com",
            
            # Education
            "coursera.org", "udemy.com", "khanacademy.org", "edx.org", "duolingo.com",
            "mit.edu", "stanford.edu", "harvard.edu", "yale.edu", "princeton.edu",
            "ox.ac.uk", "cambridge.org", "berkeley.edu", "cornell.edu", "columbia.edu",
            
            # Government
            "gov.uk", "usa.gov", "canada.ca", "irs.gov", "nih.gov",
            "cdc.gov", "fda.gov", "nasa.gov", "weather.gov", "usps.com",
            
            # Entertainment
            "imdb.com", "rottentomatoes.com", "metacritic.com", "gamespot.com", "ign.com",
            "hulu.com", "disneyplus.com", "hbomax.com", "primevideo.com", "crunchyroll.com",
            
            # Productivity
            "notion.so", "trello.com", "asana.com", "atlassian.com", "monday.com",
            "airtable.com", "miro.com", "figma.com", "canva.com", "grammarly.com",
            
            # Cloud/Storage
            "drive.google.com", "onedrive.live.com", "box.com", "mega.nz", "pcloud.com",
            
            # Communication
            "mail.google.com", "outlook.com", "protonmail.com", "mailchimp.com"
        ]
        
        urls = []
        
        # Generate many variations
        subdomains = ['www', 'en', 'blog', 'help', 'support', 'about', 'api', 'app', 
                     'docs', 'news', 'shop', 'store', 'careers', 'community', 'forum']
        
        paths = ['', '/', '/about', '/contact', '/help', '/blog', '/news', '/support',
                '/products', '/services', '/pricing', '/features', '/login', '/signup',
                '/docs', '/api', '/community', '/forum', '/faq', '/download']
        
        protocols = ['https://', 'http://']
        
        # Generate combinations
        for domain in domains:
            # Base domain
            for protocol in protocols:
                for path in paths:
                    urls.append(f"{protocol}{domain}{path}")
            
            # With subdomains
            for subdomain in subdomains:
                for protocol in protocols:
                    for path in paths[:10]:  # Fewer paths for subdomains
                        urls.append(f"{protocol}{subdomain}.{domain}{path}")
        
        # Remove duplicates
        urls = list(set(urls))
        
        print(f"[BENIGN-FEEDER] Generated {len(urls):,} unique benign URLs")
        
        return urls
    
    def stats_monitor_thread(self):
        """Monitor and display stats"""
        last_save = time.time()
        
        while self.keep_running:
            time.sleep(10)  # Update every 10 seconds
            
            with self.stats_lock:
                stats = self.stats.copy()
            
            phishing_count = len(self.phishing_data)
            benign_count = len(self.benign_data)
            
            print(f"\n{'='*70}")
            print(f"📊 PROGRESS UPDATE - {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*70}")
            print(f"Phishing URLs:")
            print(f"  • Collected: {phishing_count:,}")
            print(f"  • Checked: {stats['phishing_checked']:,}")
            print(f"  • Accessible: {stats['phishing_accessible']:,} ({stats['phishing_accessible']/max(stats['phishing_checked'],1)*100:.1f}%)")
            print(f"  • Features extracted: {stats['phishing_features_extracted']:,}")
            print(f"\nBenign URLs:")
            print(f"  • Collected: {benign_count:,}")
            print(f"  • Checked: {stats['benign_checked']:,}")
            print(f"  • Accessible: {stats['benign_accessible']:,} ({stats['benign_accessible']/max(stats['benign_checked'],1)*100:.1f}%)")
            print(f"  • Features extracted: {stats['benign_features_extracted']:,}")
            print(f"{'='*70}\n")
            
            # Save checkpoint every 5 minutes
            if time.time() - last_save > 300:
                print("💾 Saving checkpoint...")
                self.save_checkpoint()
                last_save = time.time()
    
    def collect(self, phishing_target=5000, benign_target=5000, num_workers=50):
        """Main collection with streaming processing"""
        print("=" * 70)
        print("STREAMING DATA COLLECTION")
        print("=" * 70)
        print(f"Target: {phishing_target:,} phishing + {benign_target:,} benign")
        print(f"Workers: {num_workers} parallel processors")
        print(f"Strategy: Continuous fetch → process → repeat (NO WAITING!)")
        print("=" * 70)
        
        start_time = time.time()
        
        try:
            threads = []
            
            # Start stats monitor
            stats_thread = Thread(target=self.stats_monitor_thread, daemon=True)
            stats_thread.start()
            
            # Start phishing feeder
            feeder = Thread(target=self.phishing_url_feeder_thread, args=(phishing_target,), daemon=True)
            feeder.start()
            threads.append(feeder)
            
            # Start phishing processors
            for i in range(num_workers):
                processor = Thread(target=self.phishing_processor_thread, args=(phishing_target, i), daemon=True)
                processor.start()
                threads.append(processor)
            
            # Start benign feeder
            benign_feeder = Thread(target=self.benign_url_feeder_thread, args=(benign_target,), daemon=True)
            benign_feeder.start()
            threads.append(benign_feeder)
            
            # Start benign processors
            for i in range(num_workers // 2):
                processor = Thread(target=self.benign_processor_thread, args=(benign_target, i), daemon=True)
                processor.start()
                threads.append(processor)
            
            # Wait for completion
            print("\n⏸️  Press Ctrl+C to stop and save progress\n")
            
            while (len(self.phishing_data) < phishing_target or len(self.benign_data) < benign_target):
                time.sleep(5)
                
                if len(self.phishing_data) >= phishing_target and len(self.benign_data) >= benign_target:
                    break
            
            self.keep_running = False
            
            # Wait for threads to finish
            for thread in threads:
                thread.join(timeout=10)
            
            # Final save
            self.save_checkpoint()
            
            total_time = time.time() - start_time
            
            print("\n" + "=" * 70)
            print("✅ COLLECTION COMPLETE!")
            print("=" * 70)
            print(f"Time: {total_time/60:.1f} minutes ({total_time/3600:.1f} hours)")
            print(f"Phishing URLs: {len(self.phishing_data):,}")
            print(f"Benign URLs: {len(self.benign_data):,}")
            print(f"Total: {len(self.phishing_data) + len(self.benign_data):,}")
            
            # Save final dataset
            self.save_dataset()
        
        except KeyboardInterrupt:
            print("\n\n⏸️  STOPPED BY USER")
            self.keep_running = False
            self.save_checkpoint()
            print(f"✓ Progress saved - collected {len(self.phishing_data):,} phishing + {len(self.benign_data):,} benign")
    
    def save_dataset(self):
        """Save final dataset"""
        # Combine and shuffle
        all_data = self.phishing_data + self.benign_data
        np.random.shuffle(all_data)
        
        # Split 80/20
        split_idx = int(len(all_data) * 0.8)
        train_data = all_data[:split_idx]
        val_data = all_data[split_idx:]
        
        X_train = np.array([item[1] for item in train_data])
        y_train = np.array([item[2] for item in train_data])
        
        X_val = np.array([item[1] for item in val_data])
        y_val = np.array([item[2] for item in val_data])
        
        # Save
        train_path = os.path.join(self.output_dir, "train_dataset.pkl")
        val_path = os.path.join(self.output_dir, "val_dataset.pkl")
        
        with open(train_path, 'wb') as f:
            pickle.dump({'X': X_train, 'y': y_train}, f)
        
        with open(val_path, 'wb') as f:
            pickle.dump({'X': X_val, 'y': y_val}, f)
        
        print(f"\n💾 Datasets saved:")
        print(f"  • Training: {len(X_train):,} samples → {train_path}")
        print(f"  • Validation: {len(X_val):,} samples → {val_path}")


def main():
    """Main execution"""
    print("STREAMING FRESH DATA COLLECTOR")
    print("Continuous processing - NO WAITING!")
    print("Expected time: 3-8 hours\n")
    
    # Target: 30,000 total (15K phishing + 15K benign)
    phishing_target = 15000
    benign_target = 15000
    
    print(f"Target: {phishing_target:,} phishing + {benign_target:,} benign = {phishing_target + benign_target:,} total")
    print(f"Expected time: 3-8 hours with streaming\n")
    
    user_input = input("Start streaming collection? (y/n): ").strip().lower()
    
    if user_input not in ['y', 'yes']:
        print("Cancelled")
        return
    
    collector = StreamingDataCollector()
    collector.collect(phishing_target=phishing_target, benign_target=benign_target, num_workers=50)


if __name__ == "__main__":
    main()
