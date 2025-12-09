from flask import Flask, render_template, request, jsonify, Response
import requests
import time
import os
import json
import threading
import queue
import uuid
import concurrent.futures
import re
import io
from datetime import datetime
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'proxy-checker-secret-key-2024')

# Global variables
proxy_check_queue = queue.Queue()
active_proxy_checkers = {}
proxy_test_results = {}


class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.proxy_types = []
        self.current_index = 0

    def load_mixed_proxies(self, content):
        """Load mixed proxies with auto-detection"""
        self.proxies = []
        self.proxy_types = []
        lines = content.strip().split('\n')

        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Remove protocol prefix
                proxy_line = line
                proxy_type = 'http'

                if line.startswith('http://'):
                    proxy_line = line[7:]
                    proxy_type = 'http'
                elif line.startswith('https://'):
                    proxy_line = line[8:]
                    proxy_type = 'https'
                elif line.startswith('socks4://'):
                    proxy_line = line[9:]
                    proxy_type = 'socks4'
                elif line.startswith('socks5://'):
                    proxy_line = line[10:]
                    proxy_type = 'socks5'
                elif line.startswith('socks://'):
                    proxy_line = line[8:]
                    proxy_type = 'socks5'

                # Remove authentication if present
                if '@' in proxy_line:
                    proxy_line = proxy_line.split('@')[-1]

                # Get only IP:PORT
                if ':' in proxy_line:
                    parts = proxy_line.split(':')
                    if len(parts) >= 2:
                        ip = parts[0]
                        port = parts[1]
                        # Remove path if exists
                        if '/' in port:
                            port = port.split('/')[0]

                        try:
                            int(port)
                            proxy = f"{ip}:{port}"
                            self.proxies.append(proxy)
                            self.proxy_types.append(proxy_type)
                        except:
                            continue

        return len(self.proxies)

    def get_next_proxy(self):
        """Get next proxy in rotation"""
        if not self.proxies:
            return None, 'http'

        proxy = self.proxies[self.current_index]
        proxy_type = self.proxy_types[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy, proxy_type

    def get_proxy_count(self):
        return len(self.proxies)


class ProxyChecker:
    def __init__(self, checker_id=None):
        self.checker_id = checker_id or str(uuid.uuid4())
        self.is_running = False
        self.proxy_manager = ProxyManager()
        self.current_progress = {
            'total': 0,
            'tested': 0,
            'live': 0,
            'dead': 0,
            'status': 'idle',
            'current_proxy': None,
            'results': [],
            'settings': {
                'max_workers': 20,
                'timeout': 10,
                'test_url': 'https://www.google.com'
            }
        }
        self.DEV_INFO = "Dev: @iittechnow"
        self.CHANNEL_INFO = "Channel: https://t.me/IITTECH"

    def load_proxies(self, content):
        """Load proxies from content"""
        count = self.proxy_manager.load_mixed_proxies(content)
        return count

    def get_country_from_ip(self, ip_address):
        """Get country from IP address using ip-api.com"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=country,countryCode', timeout=3)
            if response.status_code == 200:
                data = response.json()
                return data.get('country', 'Unknown')
        except:
            pass
        return "Unknown"

    def test_single_proxy(self, proxy, proxy_type, test_url='https://www.google.com', timeout=10):
        """Test a single proxy"""
        start_time = time.time()
        ip_address = None
        country = "Unknown"
        response_time = 0

        try:
            # Format proxy URL
            if proxy_type == 'http':
                proxy_url = f'http://{proxy}'
            elif proxy_type == 'https':
                proxy_url = f'https://{proxy}'
            elif proxy_type == 'socks4':
                proxy_url = f'socks4://{proxy}'
            elif proxy_type == 'socks5':
                proxy_url = f'socks5://{proxy}'
            else:
                proxy_url = f'http://{proxy}'

            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }

            # Custom headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Upgrade-Insecure-Requests': '1'
            }

            # Test proxy
            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=timeout,
                headers=headers,
                verify=False,
                allow_redirects=True
            )

            end_time = time.time()
            response_time = round((end_time - start_time) * 1000)

            if response.status_code in [200, 301, 302]:
                try:
                    if 'application/json' in response.headers.get('content-type', '').lower():
                        data = response.json()
                        ip_address = data.get('ip') or data.get('origin')
                    else:
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                        ips = re.findall(ip_pattern, response.text)
                        if ips:
                            ip_address = ips[0]
                except:
                    ip_address = proxy.split(':')[0]

                if ip_address:
                    country = self.get_country_from_ip(ip_address)

                return {
                    'proxy': proxy,
                    'proxy_type': proxy_type.upper(),
                    'status': 'LIVE',
                    'response_time': response_time,
                    'ip_address': ip_address,
                    'country': country,
                    'response_code': response.status_code,
                    'message': f'LIVE | {response_time}ms | {country}'
                }
            else:
                return {
                    'proxy': proxy,
                    'proxy_type': proxy_type.upper(),
                    'status': 'DEAD',
                    'response_time': response_time,
                    'ip_address': None,
                    'country': 'Unknown',
                    'response_code': response.status_code,
                    'message': f'DEAD | HTTP {response.status_code}'
                }

        except requests.exceptions.Timeout:
            end_time = time.time()
            response_time = round((end_time - start_time) * 1000)
            return {
                'proxy': proxy,
                'proxy_type': proxy_type.upper(),
                'status': 'DEAD',
                'response_time': response_time,
                'ip_address': None,
                'country': 'Unknown',
                'response_code': 0,
                'message': f'DEAD | Timeout ({response_time}ms)'
            }
        except requests.exceptions.ConnectionError:
            end_time = time.time()
            response_time = round((end_time - start_time) * 1000)
            return {
                'proxy': proxy,
                'proxy_type': proxy_type.upper(),
                'status': 'DEAD',
                'response_time': response_time,
                'ip_address': None,
                'country': 'Unknown',
                'response_code': 0,
                'message': f'DEAD | Connection Failed'
            }
        except Exception as e:
            end_time = time.time()
            response_time = round((end_time - start_time) * 1000)
            error_msg = str(e)
            if 'Cannot connect to proxy' in error_msg:
                error_msg = 'Cannot connect to proxy'
            elif 'SOCKS' in error_msg:
                error_msg = 'SOCKS connection failed'
            elif 'Max retries exceeded' in error_msg:
                error_msg = 'Max retries exceeded'

            return {
                'proxy': proxy,
                'proxy_type': proxy_type.upper(),
                'status': 'DEAD',
                'response_time': response_time,
                'ip_address': None,
                'country': 'Unknown',
                'response_code': 0,
                'message': f'DEAD | {error_msg[:30]}'
            }

    def start_checking(self, max_workers=20, timeout=10, test_url='https://www.google.com'):
        """Start checking all proxies"""
        self.is_running = True

        self.current_progress['settings'] = {
            'max_workers': max_workers,
            'timeout': timeout,
            'test_url': test_url
        }

        self.current_progress.update({
            'total': len(self.proxy_manager.proxies),
            'tested': 0,
            'live': 0,
            'dead': 0,
            'status': 'running',
            'current_proxy': None,
            'results': []
        })

        # Initial progress
        proxy_check_queue.put({
            'checker_id': self.checker_id,
            'progress': self.current_progress.copy(),
            'dev_info': self.DEV_INFO,
            'channel_info': self.CHANNEL_INFO
        })

        # Use ThreadPoolExecutor for concurrent checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []

            for i, (proxy, proxy_type) in enumerate(zip(self.proxy_manager.proxies, self.proxy_manager.proxy_types)):
                if not self.is_running:
                    break

                future = executor.submit(
                    self.test_single_proxy,
                    proxy,
                    proxy_type,
                    test_url,
                    timeout
                )
                futures.append((i, future))

            # Process results as they complete
            for i, future in futures:
                if not self.is_running:
                    break

                try:
                    result = future.result(timeout=timeout + 5)

                    self.current_progress['tested'] += 1
                    self.current_progress['current_proxy'] = f"{result['proxy']} ({result['proxy_type']})"

                    if result['status'] == 'LIVE':
                        self.current_progress['live'] += 1
                    else:
                        self.current_progress['dead'] += 1

                    self.current_progress['results'].append(result)

                    # Progress update every 10 proxies or on live proxy
                    if self.current_progress['tested'] % 10 == 0 or result['status'] == 'LIVE':
                        proxy_check_queue.put({
                            'checker_id': self.checker_id,
                            'progress': self.current_progress.copy(),
                            'dev_info': self.DEV_INFO,
                            'channel_info': self.CHANNEL_INFO
                        })

                except Exception as e:
                    self.current_progress['tested'] += 1
                    self.current_progress['dead'] += 1

                    self.current_progress['results'].append({
                        'proxy': self.proxy_manager.proxies[i],
                        'proxy_type': self.proxy_manager.proxy_types[i].upper(),
                        'status': 'DEAD',
                        'response_time': 0,
                        'ip_address': None,
                        'country': 'Unknown',
                        'response_code': 0,
                        'message': 'Test Error'
                    })

        if self.is_running:
            self.current_progress['status'] = 'completed'
            proxy_check_queue.put({
                'checker_id': self.checker_id,
                'progress': self.current_progress.copy(),
                'final': True,
                'dev_info': self.DEV_INFO,
                'channel_info': self.CHANNEL_INFO
            })

        # Store results globally
        proxy_test_results[self.checker_id] = {
            'results': self.current_progress['results'],
            'stats': {
                'total': self.current_progress['total'],
                'live': self.current_progress['live'],
                'dead': self.current_progress['dead']
            },
            'dev_info': self.DEV_INFO,
            'channel_info': self.CHANNEL_INFO,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'test_url': test_url
        }

        self.is_running = False

        if self.checker_id in active_proxy_checkers:
            del active_proxy_checkers[self.checker_id]

    def stop_checking(self):
        self.is_running = False
        self.current_progress['status'] = 'stopped'
        proxy_check_queue.put({
            'checker_id': self.checker_id,
            'progress': self.current_progress.copy(),
            'stopped': True,
            'dev_info': self.DEV_INFO,
            'channel_info': self.CHANNEL_INFO
        })


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/start-proxy-check', methods=['POST'])
def start_proxy_check():
    data = request.json
    proxy_content = data.get('proxy_content', '').strip()
    max_workers = int(data.get('max_workers', 20))
    timeout = int(data.get('timeout', 10))
    test_url = data.get('test_url', 'https://www.google.com')

    if not proxy_content:
        return jsonify({
            'success': False,
            'message': 'Proxy list is empty',
            'checker_id': None
        })

    # Validate inputs
    if max_workers < 1:
        max_workers = 1
    elif max_workers > 50:  # Reduced for Vercel
        max_workers = 50

    if timeout < 1:
        timeout = 1
    elif timeout > 30:
        timeout = 30

    # Auto-add https:// if missing
    if test_url and not test_url.startswith(('http://', 'https://')):
        test_url = 'https://' + test_url

    # Create proxy checker
    proxy_checker = ProxyChecker()
    active_proxy_checkers[proxy_checker.checker_id] = proxy_checker

    # Load proxies
    proxy_count = proxy_checker.load_proxies(proxy_content)

    if proxy_count == 0:
        return jsonify({
            'success': False,
            'message': 'No valid proxies found in the list',
            'checker_id': None
        })

    # Start checking in background thread
    thread = threading.Thread(
        target=proxy_checker.start_checking,
        args=(max_workers, timeout, test_url)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'message': f'Proxy checking started! Testing {proxy_count} proxies with {max_workers} workers against: {test_url}',
        'checker_id': proxy_checker.checker_id,
        'proxy_count': proxy_count,
        'dev_info': proxy_checker.DEV_INFO,
        'channel_info': proxy_checker.CHANNEL_INFO
    })


@app.route('/api/stop-proxy-check', methods=['POST'])
def stop_proxy_check():
    data = request.json
    checker_id = data.get('checker_id')

    if not checker_id or checker_id not in active_proxy_checkers:
        return jsonify({
            'success': False,
            'message': 'Proxy checker not found'
        })

    proxy_checker = active_proxy_checkers[checker_id]
    proxy_checker.stop_checking()

    return jsonify({
        'success': True,
        'message': 'Proxy checker stopped'
    })


@app.route('/api/proxy-progress/<checker_id>')
def get_proxy_progress(checker_id):
    def generate():
        while True:
            try:
                item = proxy_check_queue.get(timeout=1)
                if item['checker_id'] == checker_id:
                    yield f"data: {json.dumps(item)}\n\n"
                    if item.get('final', False) or item.get('stopped', False):
                        break
            except queue.Empty:
                if checker_id not in active_proxy_checkers:
                    break
                yield "data: {}\n\n"

    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/get-proxy-results/<checker_id>')
def get_proxy_results(checker_id):
    if checker_id in proxy_test_results:
        results = proxy_test_results[checker_id]
        return jsonify({
            'success': True,
            'results': results
        })
    elif checker_id in active_proxy_checkers:
        proxy_checker = active_proxy_checkers[checker_id]
        return jsonify({
            'success': True,
            'results': {
                'results': proxy_checker.current_progress['results'],
                'stats': {
                    'total': proxy_checker.current_progress['total'],
                    'live': proxy_checker.current_progress['live'],
                    'dead': proxy_checker.current_progress['dead']
                },
                'dev_info': proxy_checker.DEV_INFO,
                'channel_info': proxy_checker.CHANNEL_INFO
            }
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Results not found'
        })


@app.route('/api/proxy-check-status/<checker_id>')
def proxy_check_status(checker_id):
    if checker_id in active_proxy_checkers:
        proxy_checker = active_proxy_checkers[checker_id]
        return jsonify({
            'exists': True,
            'status': proxy_checker.current_progress['status'],
            'total': proxy_checker.current_progress['total'],
            'tested': proxy_checker.current_progress['tested'],
            'live': proxy_checker.current_progress['live'],
            'dead': proxy_checker.current_progress['dead']
        })
    elif checker_id in proxy_test_results:
        return jsonify({
            'exists': True,
            'status': 'completed'
        })
    else:
        return jsonify({
            'exists': False,
            'status': 'not_found'
        })


@app.route('/api/download-live-proxies/<checker_id>')
def download_live_proxies(checker_id):
    if checker_id in proxy_test_results:
        results = proxy_test_results[checker_id]
    elif checker_id in active_proxy_checkers:
        proxy_checker = active_proxy_checkers[checker_id]
        results = {
            'results': proxy_checker.current_progress['results'],
            'stats': proxy_checker.current_progress,
            'dev_info': proxy_checker.DEV_INFO,
            'channel_info': proxy_checker.CHANNEL_INFO,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'test_url': proxy_checker.current_progress['settings']['test_url']
        }
    else:
        return jsonify({
            'success': False,
            'message': 'Results not found'
        })

    # Create text content
    output = io.StringIO()
    output.write(f"# Proxy Checker Results\n")
    output.write(f"# {results['dev_info']}\n")
    output.write(f"# {results['channel_info']}\n")
    output.write(f"# Generated: {results.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n")
    output.write(f"# Test URL: {results.get('test_url', 'https://www.google.com')}\n")
    output.write(f"# Total Proxies: {results['stats']['total']}\n")
    output.write(f"# Live Proxies: {results['stats']['live']}\n")
    output.write(f"# Dead Proxies: {results['stats']['dead']}\n")
    output.write("#" * 80 + "\n\n")

    output.write("[ LIVE PROXIES ]\n")
    output.write("=" * 80 + "\n")

    live_count = 0
    for proxy in results['results']:
        if proxy['status'] == 'LIVE':
            live_count += 1
            external_ip = proxy.get('ip_address', 'N/A')
            country = proxy.get('country', 'Unknown')
            output.write(
                f"{proxy['proxy']} | Type: {proxy['proxy_type']} | Status: {proxy['status']} | Time: {proxy['response_time']}ms | Country: {country} | IP: {external_ip}\n")

    output.write(f"\nTotal Live: {live_count}\n\n")

    output.write("[ DEAD PROXIES ]\n")
    output.write("=" * 80 + "\n")

    dead_count = 0
    for proxy in results['results']:
        if proxy['status'] == 'DEAD':
            dead_count += 1
            output.write(
                f"{proxy['proxy']} | Type: {proxy['proxy_type']} | Status: {proxy['status']} | Error: {proxy['message']}\n")

    output.write(f"\nTotal Dead: {dead_count}\n")

    # Create response
    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    return Response(
        output.getvalue(),
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename=proxy_results_{timestamp}.txt',
            'Content-Type': 'text/plain; charset=utf-8'
        }
    )


@app.route('/api/download-only-live/<checker_id>')
def download_only_live(checker_id):
    if checker_id in proxy_test_results:
        results = proxy_test_results[checker_id]
    elif checker_id in active_proxy_checkers:
        proxy_checker = active_proxy_checkers[checker_id]
        results = {
            'results': proxy_checker.current_progress['results'],
            'dev_info': proxy_checker.DEV_INFO,
            'channel_info': proxy_checker.CHANNEL_INFO,
            'test_url': proxy_checker.current_progress['settings']['test_url']
        }
    else:
        return jsonify({
            'success': False,
            'message': 'Results not found'
        })

    # Create text content with only live proxies
    output = io.StringIO()
    output.write(f"# Live Proxies Only\n")
    output.write(f"# {results['dev_info']}\n")
    output.write(f"# {results['channel_info']}\n")
    output.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    output.write(f"# Test URL: {results.get('test_url', 'https://www.google.com')}\n")
    output.write("#" * 80 + "\n\n")

    # Group proxies by type
    http_proxies = []
    https_proxies = []
    socks4_proxies = []
    socks5_proxies = []

    live_count = 0
    for proxy in results['results']:
        if proxy['status'] == 'LIVE':
            live_count += 1
            if proxy['proxy_type'] == 'HTTP':
                http_proxies.append(proxy['proxy'])
            elif proxy['proxy_type'] == 'HTTPS':
                https_proxies.append(proxy['proxy'])
            elif proxy['proxy_type'] == 'SOCKS4':
                socks4_proxies.append(proxy['proxy'])
            elif proxy['proxy_type'] == 'SOCKS5':
                socks5_proxies.append(proxy['proxy'])

    # Write HTTP proxies
    if http_proxies:
        output.write("http\n\n")
        for proxy in http_proxies:
            output.write(f"{proxy}\n")
        output.write("\n")

    # Write HTTPS proxies
    if https_proxies:
        output.write("https\n\n")
        for proxy in https_proxies:
            output.write(f"{proxy}\n")
        output.write("\n")

    # Write SOCKS4 proxies
    if socks4_proxies:
        output.write("socks4\n\n")
        for proxy in socks4_proxies:
            output.write(f"{proxy}\n")
        output.write("\n")

    # Write SOCKS5 proxies
    if socks5_proxies:
        output.write("socks5\n\n")
        for proxy in socks5_proxies:
            output.write(f"{proxy}\n")
        output.write("\n")

    output.write(f"# Total Live Proxies: {live_count}\n")

    # Create response
    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    return Response(
        output.getvalue(),
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename=live_proxies_{timestamp}.txt',
            'Content-Type': 'text/plain; charset=utf-8'
        }
    )


@app.route('/api/sample-proxies')
def sample_proxies():
    sample = """# Proxy List Format (One per line)
# Support: HTTP, HTTPS, SOCKS4, SOCKS5 proxies
# Developer: @iittechnow
# Channel: https://t.me/IITTECH

# Example proxies:
http://123.45.67.89:8080
https://secure.proxy.com:3128
socks4://111.222.333.444:1080
socks5://222.333.444.555:1080
192.168.1.100:8080  # Will be treated as HTTP
45.76.89.12:1080
socks://proxy.example.com:9150

# Add your proxies below:"""

    return jsonify({
        'success': True,
        'sample': sample
    })


@app.route('/api/test-urls')
def get_test_urls():
    """Get list of popular test URLs"""
    test_urls = [
        {'name': 'Google', 'url': 'https://www.google.com'},
        {'name': 'HttpBin IP', 'url': 'https://httpbin.org/ip'},
        {'name': 'HttpBin User-Agent', 'url': 'https://httpbin.org/user-agent'},
        {'name': 'Amazon', 'url': 'https://www.amazon.com'},
        {'name': 'YouTube', 'url': 'https://www.youtube.com'},
        {'name': 'GitHub', 'url': 'https://github.com'},
        {'name': 'StackOverflow', 'url': 'https://stackoverflow.com'},
        {'name': 'Wikipedia', 'url': 'https://www.wikipedia.org'},
        {'name': 'DuckDuckGo', 'url': 'https://duckduckgo.com'},
        {'name': 'Reddit', 'url': 'https://www.reddit.com'}
    ]

    return jsonify({
        'success': True,
        'test_urls': test_urls
    })


@app.route('/api/upload-proxies', methods=['POST'])
def upload_proxies():
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'message': 'No file uploaded'
        })

    file = request.files['file']
    if file.filename == '':
        return jsonify({
            'success': False,
            'message': 'No file selected'
        })

    if file:
        try:
            content = file.read().decode('utf-8', errors='ignore')
        except:
            try:
                content = file.read().decode('latin-1', errors='ignore')
            except:
                return jsonify({
                    'success': False,
                    'message': 'Failed to read file'
                })

        # Parse proxies
        proxy_manager = ProxyManager()
        proxy_count = proxy_manager.load_mixed_proxies(content)

        return jsonify({
            'success': True,
            'message': f'Proxy file uploaded. Found {proxy_count} proxies.',
            'proxy_count': proxy_count,
            'content': content
        })

    return jsonify({
        'success': False,
        'message': 'File upload failed'
    })


@app.route('/api/clear-checker/<checker_id>', methods=['POST'])
def clear_checker(checker_id):
    if checker_id in active_proxy_checkers:
        del active_proxy_checkers[checker_id]

    if checker_id in proxy_test_results:
        del proxy_test_results[checker_id]

    return jsonify({
        'success': True,
        'message': 'Checker cleared'
    })


@app.route('/api/get-stats')
def get_stats():
    total_checkers = len(active_proxy_checkers)
    completed_checkers = len(proxy_test_results)

    total_proxies_tested = 0
    total_live_proxies = 0

    for checker_id in proxy_test_results:
        stats = proxy_test_results[checker_id]['stats']
        total_proxies_tested += stats['total']
        total_live_proxies += stats['live']

    return jsonify({
        'success': True,
        'stats': {
            'active_checkers': total_checkers,
            'completed_checkers': completed_checkers,
            'total_proxies_tested': total_proxies_tested,
            'total_live_proxies_found': total_live_proxies
        }
    })


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'success': False,
        'message': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'

    print("=" * 60)
    print("PROXY CHECKER BY @iittechnow")
    print("Channel: https://t.me/IITTECH")
    print("=" * 60)
    print(f"Access the application at: http://localhost:{port}")
    print("\nDefault Test URL: https://www.google.com")
    print("You can change the Test URL in the settings")
    print("-" * 60)

    app.run(debug=debug, host='0.0.0.0', port=port, threaded=True)