# Next.js RSC (React Server Components) Wire Format Parser for Burp Suite
# Author: Security Assessment Tool
# Compatible with Burp Suite Pro/Community using Jython
#
# Installation:
#   1. Ensure Jython is configured in Burp (Extender > Options > Python Environment)
#   2. Load this file via Extender > Extensions > Add
#
# Usage:
#   - RSC responses will show a new "RSC Parsed" tab in the message editor
#   - Right-click responses to extract chunk URLs or analyze components

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, IContextMenuFactory, IHttpListener
from javax.swing import JMenuItem, JPanel, JScrollPane, JTextArea, JTabbedPane, JSplitPane, JTree, JLabel
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel
from java.awt import BorderLayout, Font, Color
from java.util import ArrayList
import re
import json
import threading

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Next.js RSC Parser")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        
        # Storage for discovered chunks and components
        self.discovered_chunks = set()
        self.discovered_components = {}
        self.discovered_routes = {}
        
        print("[+] Next.js RSC Parser loaded")
        print("[+] Registers editor tab for text/x-component responses")
        print("[+] Right-click for chunk extraction and analysis options")
    
    def createNewInstance(self, controller, editable):
        return RSCEditorTab(self, controller, editable)
    
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        
        # Only show for responses
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
        ]:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                response = messages[0].getResponse()
                if response and self._is_rsc_response(response):
                    
                    extract_chunks = JMenuItem("Extract Chunk URLs")
                    extract_chunks.addActionListener(
                        lambda e: self._extract_chunks_action(messages[0])
                    )
                    menu_items.add(extract_chunks)
                    
                    analyze_components = JMenuItem("Analyze Components (Security)")
                    analyze_components.addActionListener(
                        lambda e: self._analyze_security_action(messages[0])
                    )
                    menu_items.add(analyze_components)
                    
                    export_parsed = JMenuItem("Export Parsed RSC")
                    export_parsed.addActionListener(
                        lambda e: self._export_parsed_action(messages[0])
                    )
                    menu_items.add(export_parsed)
        
        return menu_items
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Passive listener to track RSC responses"""
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response and self._is_rsc_response(response):
                url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                body = self._get_response_body(response)
                parsed = RSCParser.parse(body)
                
                # Track discovered resources
                for chunk in parsed.get('chunks', []):
                    self.discovered_chunks.add(chunk)
                
                for comp_name, comp_data in parsed.get('components', {}).items():
                    self.discovered_components[comp_name] = comp_data
                
                route_params = parsed.get('route_params', {})
                if route_params:
                    self.discovered_routes[url] = route_params
    
    def _is_rsc_response(self, response):
        """Check if response is RSC format"""
        analyzed = self._helpers.analyzeResponse(response)
        headers = analyzed.getHeaders()
        
        for header in headers:
            header_lower = header.lower()
            if 'content-type' in header_lower:
                if 'text/x-component' in header_lower:
                    return True
                if 'application/octet-stream' in header_lower:
                    # Could be RSC, check body
                    body = self._get_response_body(response)
                    return self._looks_like_rsc(body)
        
        # Fallback: check body pattern
        body = self._get_response_body(response)
        return self._looks_like_rsc(body)
    
    def _looks_like_rsc(self, body):
        """Heuristic check for RSC format"""
        if not body:
            return False
        lines = body.split('\n')
        rsc_pattern = re.compile(r'^[0-9a-fA-F]+:')
        matches = sum(1 for line in lines[:10] if rsc_pattern.match(line))
        return matches >= 2
    
    def _get_response_body(self, response):
        """Extract response body as string"""
        analyzed = self._helpers.analyzeResponse(response)
        body_offset = analyzed.getBodyOffset()
        body_bytes = response[body_offset:]
        try:
            return self._helpers.bytesToString(body_bytes)
        except:
            return str(bytearray(body_bytes))
    
    def _extract_chunks_action(self, message_info):
        """Extract and print all chunk URLs"""
        response = message_info.getResponse()
        body = self._get_response_body(response)
        parsed = RSCParser.parse(body)
        
        base_url = self._helpers.analyzeRequest(message_info).getUrl()
        base = "%s://%s" % (base_url.getProtocol(), base_url.getHost())
        if base_url.getPort() not in [-1, 80, 443]:
            base += ":%d" % base_url.getPort()
        
        print("\n" + "="*60)
        print("[+] EXTRACTED CHUNK URLs")
        print("="*60)
        
        chunks = parsed.get('chunks', [])
        for chunk in sorted(set(chunks)):
            full_url = base + chunk if chunk.startswith('/') else chunk
            print(full_url)
        
        print("\n[+] Total: %d unique chunks" % len(set(chunks)))
        print("[*] Copy these to Burp Intruder or use 'Send to Repeater' for analysis")
    
    def _analyze_security_action(self, message_info):
        """Perform security-focused analysis"""
        response = message_info.getResponse()
        body = self._get_response_body(response)
        parsed = RSCParser.parse(body)
        
        print("\n" + "="*60)
        print("[+] SECURITY ANALYSIS")
        print("="*60)
        
        # Route parameters (potential IDOR targets)
        params = parsed.get('route_params', {})
        if params:
            print("\n[!] Route Parameters (IDOR candidates):")
            for key, value in params.items():
                print("    %s = %s" % (key, value))
                self._analyze_id_format(key, value)
        
        # Component analysis
        components = parsed.get('components', {})
        if components:
            print("\n[!] Exposed Components (data model inference):")
            for name in sorted(components.keys()):
                print("    - %s" % name)
                # Flag interesting component patterns
                if any(x in name.lower() for x in ['auth', 'admin', 'user', 'role', 'permission']):
                    print("      ^ INTERESTING: May contain auth/authz logic")
                if any(x in name.lower() for x in ['provider', 'context']):
                    print("      ^ State management - check for sensitive data exposure")
        
        # Metadata analysis
        metadata = parsed.get('metadata', {})
        if metadata:
            print("\n[!] Metadata:")
            for key, value in metadata.items():
                print("    %s: %s" % (key, value[:100] if isinstance(value, str) else value))
        
        # Raw data structures
        data_structures = parsed.get('data_structures', [])
        if data_structures:
            print("\n[!] Embedded Data Structures (%d found):" % len(data_structures))
            for i, ds in enumerate(data_structures[:5]):  # Limit output
                print("    [%d] %s..." % (i, str(ds)[:200]))
    
    def _analyze_id_format(self, key, value):
        """Analyze ID format for enumeration potential"""
        if not isinstance(value, str):
            return
        
        # Check for common ID patterns
        if re.match(r'^[0-9]+$', value):
            print("      ^ Sequential numeric ID - HIGH enumeration risk")
        elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', value, re.I):
            print("      ^ UUID format - lower enumeration risk, but check version")
        elif re.match(r'^[A-Za-z0-9]{20,}$', value):
            print("      ^ Firestore-style ID - pseudo-random, check for patterns")
        elif re.match(r'^[A-Za-z0-9_-]{10,}$', value):
            print("      ^ Base64-ish ID - may be decodable")
    
    def _export_parsed_action(self, message_info):
        """Export parsed data as JSON"""
        response = message_info.getResponse()
        body = self._get_response_body(response)
        parsed = RSCParser.parse(body)
        
        print("\n" + "="*60)
        print("[+] PARSED RSC EXPORT (JSON)")
        print("="*60)
        print(json.dumps(parsed, indent=2, default=str))


class RSCParser:
    """
    Parser for Next.js React Server Components wire format.
    
    Format overview:
    - Line-based, each line is: ID:PAYLOAD
    - ID is typically hex or decimal
    - PAYLOAD types:
        - I[chunk_id, [chunks], "export"] - Client component import
        - $Sreact.fragment / $Sreact.suspense - React symbols
        - $L{id} - Lazy reference to another line
        - $undefined - Undefined value
        - JSON arrays/objects - Data structures
        - Quoted strings - String values
    """
    
    # Patterns for parsing
    LINE_PATTERN = re.compile(r'^([0-9a-fA-F]+):(.*)$')
    IMPORT_PATTERN = re.compile(r'^I\[(\d+),\s*\[(.*?)\],\s*"([^"]+)"\]')
    SYMBOL_PATTERN = re.compile(r'^\$S(.+)$')
    LAZY_REF_PATTERN = re.compile(r'\$L([0-9a-fA-F]+)')
    CHUNK_PATH_PATTERN = re.compile(r'"((?:/_next/|/)?static/chunks/[^"]+\.js)"')
    ROUTE_PARAM_PATTERN = re.compile(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*,\s*"([^"]+)"')
    # Server action pattern - $F references bound server functions
    SERVER_ACTION_PATTERN = re.compile(r'\$F([0-9a-fA-F]+)')
    # React element pattern ["$","type","key",{props}] or ["$","type","key",{props},children]
    REACT_ELEMENT_PATTERN = re.compile(r'\["\$"\s*,\s*"([^"]+)"\s*,\s*("[^"]*"|null)\s*,\s*(\{[^}]*\}|\$L[0-9a-fA-F]+|null)')
    
    @classmethod
    def parse(cls, raw_body):
        """
        Parse RSC wire format into structured data.
        
        Returns dict with:
            - lines: Raw parsed lines {id: content}
            - chunks: List of chunk URLs
            - components: Dict of component names -> metadata
            - route_params: Extracted route parameters
            - metadata: Page metadata (title, description, etc.)
            - data_structures: Embedded JSON structures
            - references: Cross-references between lines
        """
        result = {
            'lines': {},
            'chunks': [],
            'components': {},
            'route_params': {},
            'route_tree': [],
            'metadata': {},
            'data_structures': [],
            'references': {},
            'raw_line_count': 0,
            # New fields for enhanced extraction
            'flight_manifest': {},      # Parsed line 0 flight data
            'server_actions': [],       # $F server action references
            'exposed_data': [],         # Actual data values found (security relevant)
            'component_props': {},      # Props passed to each component
            'resolved_tree': [],        # Resolved component tree with data
            'text_content': [],         # Meaningful text strings rendered on page
            'entity_arrays': [],        # Arrays of records
        }
        
        if not raw_body:
            return result
        
        lines = raw_body.split('\n')
        result['raw_line_count'] = len(lines)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            match = cls.LINE_PATTERN.match(line)
            if match:
                line_id = match.group(1)
                content = match.group(2)
                result['lines'][line_id] = content
                
                # Parse content based on type
                cls._parse_line_content(line_id, content, result)
            else:
                # Some responses have non-ID prefixed lines
                cls._parse_inline_content(line, result)
        
        # Post-processing
        cls._extract_metadata(result)
        cls._parse_flight_manifest(result)
        cls._resolve_references(result)
        cls._extract_text_and_entities(result)
        cls._scan_for_sensitive_values(result)
        cls._extract_exposed_data(result)

        return result

    @classmethod
    def _scan_for_sensitive_values(cls, result):
        """Scan all content for sensitive value patterns (JWTs, API keys, etc.)"""
        # Patterns that indicate sensitive data regardless of context
        sensitive_patterns = [
            (r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+', 'JWT'),
            (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Secret Key'),
            (r'sk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Key'),
            (r'pk_live_[a-zA-Z0-9]{24,}', 'Stripe Publishable Key'),
            (r'rk_live_[a-zA-Z0-9]{24,}', 'Stripe Restricted Key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token'),
            (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
            (r'github_pat_[a-zA-Z0-9_]{22,}', 'GitHub PAT'),
            (r'xox[baprs]-[a-zA-Z0-9-]{10,}', 'Slack Token'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'ya29\.[a-zA-Z0-9_-]+', 'Google OAuth Token'),
            (r'AIza[a-zA-Z0-9_-]{35}', 'Google API Key'),
            (r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+', 'Credentials in URL'),
            (r'bearer\s+[a-zA-Z0-9_-]{20,}', 'Bearer Token'),
            (r'api[_-]?key["\s:=]+[a-zA-Z0-9_-]{16,}', 'API Key'),
            (r'secret["\s:=]+[a-zA-Z0-9_-]{16,}', 'Secret'),
            (r'password["\s:=]+[^\s"]{4,}', 'Password'),
        ]

        # Scan all raw lines
        for line_id, content in result.get('lines', {}).items():
            for pattern, name in sensitive_patterns:
                for match in re.finditer(pattern, content, re.I):
                    value = match.group(0)
                    result['exposed_data'].append({
                        'path': 'line_%s' % line_id,
                        'data': {name: value[:500]},
                        'is_sensitive': True,
                        'keys': [name],
                        'reasons': ['value_pattern:%s' % name]
                    })

        # Also scan the flight manifest JSON string representation
        manifest = result.get('flight_manifest', {})
        if manifest:
            manifest_str = json.dumps(manifest, default=str)
            for pattern, name in sensitive_patterns:
                for match in re.finditer(pattern, manifest_str, re.I):
                    value = match.group(0)
                    # Avoid duplicates
                    already_found = any(
                        name in item.get('keys', []) and value[:50] in str(item.get('data', ''))
                        for item in result['exposed_data']
                    )
                    if not already_found:
                        result['exposed_data'].append({
                            'path': 'flight_manifest',
                            'data': {name: value[:500]},
                            'is_sensitive': True,
                            'keys': [name],
                            'reasons': ['value_pattern:%s' % name]
                        })

    @classmethod
    def _extract_text_and_entities(cls, result):
        """Extract text content and entity arrays from resolved structures"""
        for line_id, data in result.get('resolved_tree', {}).items():
            cls._extract_text_content(data, result, 'line_%s' % line_id)
            cls._extract_entity_arrays(data, result, 'line_%s' % line_id)

        # Also scan data_structures
        for ds in result.get('data_structures', []):
            data = ds.get('data', {})
            cls._extract_text_content(data, result, 'ds_%s' % ds.get('line_id', '?'))
            cls._extract_entity_arrays(data, result, 'ds_%s' % ds.get('line_id', '?'))

        # Scan raw lines for quoted strings (catches text we might have missed)
        cls._extract_text_from_raw_lines(result)

    @classmethod
    def _extract_text_from_raw_lines(cls, result):
        """Extract text content directly from raw RSC lines"""
        # Pattern to find "children":"some text"
        children_pattern = re.compile(r'"children"\s*:\s*"([^"]{2,})"')

        # Pattern to find "content":"actual content" in meta tags
        content_pattern = re.compile(r'"content"\s*:\s*"([^"]{2,})"')

        # Pattern for title tags: ["$","title","0",{"children":"Page Title"}]
        title_pattern = re.compile(r'\["\$"\s*,\s*"title"\s*,[^,]+,\s*\{\s*"children"\s*:\s*"([^"]+)"')

        # Pattern for href/src URLs that might be interesting
        url_pattern = re.compile(r'"(href|src|url|image|icon)"\s*:\s*"(https?://[^"]+)"', re.I)

        for line_id, content in result.get('lines', {}).items():
            # Find children text
            for match in children_pattern.finditer(content):
                text = match.group(1)
                text = text.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
                if not cls._is_noise_text(text):
                    result.setdefault('text_content', []).append({
                        'path': 'raw_%s.children' % line_id,
                        'text': text[:500]
                    })

            # Find content values (from meta tags etc)
            for match in content_pattern.finditer(content):
                text = match.group(1)
                text = text.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
                if not cls._is_noise_text(text):
                    result.setdefault('text_content', []).append({
                        'path': 'raw_%s.content' % line_id,
                        'text': text[:500]
                    })

            # Find title content
            for match in title_pattern.finditer(content):
                text = match.group(1)
                text = text.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
                if not cls._is_noise_text(text):
                    result.setdefault('text_content', []).append({
                        'path': 'raw_%s.title' % line_id,
                        'text': text[:500]
                    })

            # Find URLs (can reveal environments, internal services)
            for match in url_pattern.finditer(content):
                url_type = match.group(1)
                url = match.group(2)
                result.setdefault('text_content', []).append({
                    'path': 'raw_%s.%s' % (line_id, url_type),
                    'text': url[:500]
                })
    
    @classmethod
    def _parse_line_content(cls, line_id, content, result):
        """Parse individual line content"""
        
        # Client component imports
        if content.startswith('I['):
            cls._parse_import(content, result)
            # Also extract routes from chunk paths in imports
            cls._extract_route_tree(content, result)
            return
        
        # React symbols
        if content.startswith('"$S'):
            symbol_match = cls.SYMBOL_PATTERN.match(content[1:-1])
            if symbol_match:
                result['components']['_symbol_' + line_id] = symbol_match.group(1)
            return
        
        # JSON structures
        if content.startswith('{') or content.startswith('[') or content.startswith('["$"'):
            cls._parse_json_structure(line_id, content, result)
            return
        
        # Extract any chunk paths
        chunk_matches = cls.CHUNK_PATH_PATTERN.findall(content)
        result['chunks'].extend(chunk_matches)

        # Extract route params from common patterns
        cls._extract_route_params(content, result)

        # Extract lazy references
        lazy_refs = cls.LAZY_REF_PATTERN.findall(content)
        if lazy_refs:
            result['references'][line_id] = lazy_refs

        # Extract server action references ($F)
        server_actions = cls.SERVER_ACTION_PATTERN.findall(content)
        for action_id in server_actions:
            result['server_actions'].append({
                'id': action_id,
                'found_in_line': line_id,
                'context': content[:200]
            })
    
    @classmethod
    def _parse_import(cls, content, result):
        """Parse I[...] import statements"""
        # Extract component info
        # Format: I[chunk_id, [chunk_paths], "ComponentName"]
        
        # Get chunk paths
        chunks = cls.CHUNK_PATH_PATTERN.findall(content)
        result['chunks'].extend(chunks)
        
        # Get component name (last quoted string usually)
        quoted_strings = re.findall(r'"([^"]+)"', content)
        if quoted_strings:
            component_name = quoted_strings[-1]
            if not component_name.startswith('/') and not component_name.startswith('static'):
                result['components'][component_name] = {
                    'chunks': chunks[:3] if chunks else [],  # First few chunks
                    'chunk_count': len(chunks)
                }
    
    @classmethod
    def _parse_json_structure(cls, line_id, content, result):
        """Parse JSON-like structures"""
        try:
            # RSC uses some non-standard JSON, try to clean it up
            cleaned = content
            # Replace $L references with placeholder
            cleaned = re.sub(r'\$L([0-9a-fA-F]+)', r'"__REF_\1__"', cleaned)
            # Replace $undefined
            cleaned = cleaned.replace('$undefined', 'null')
            # Replace $S symbols
            cleaned = re.sub(r'\$S([a-zA-Z.]+)', r'"__SYMBOL_\1__"', cleaned)
            
            parsed = json.loads(cleaned)
            result['data_structures'].append({
                'line_id': line_id,
                'data': parsed
            })
            
            # Extract route params from parsed data
            cls._extract_params_from_structure(parsed, result)
            
        except ValueError:
            # Not valid JSON, store raw
            pass
    
    @classmethod
    def _extract_route_params(cls, content, result):
        """Extract route parameters from content"""
        # Generic patterns for route parameters in RSC format
        param_patterns = [
            # Next.js dynamic route array format: ["paramName","value","d"] - the "d" suffix indicates dynamic segment
            r'\["([a-zA-Z_][a-zA-Z0-9_]*)"\s*,\s*"([A-Za-z0-9_-]{6,})"\s*,\s*"d"\]',
            # Generic param with Id/ID suffix: "someId","value" or "someID": "value"
            r'"([a-zA-Z_][a-zA-Z0-9_]*(?:Id|ID))"\s*[,:"]\s*"([A-Za-z0-9_-]{6,})"',
            # Params object: "params":{"key":"value"}
            r'"params"\s*:\s*\{\s*"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:\s*"([^"]+)"\s*\}',
            # SearchParams: "searchParams":{"key":"value"}
            r'"searchParams"\s*:\s*\{\s*"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:\s*"([^"]+)"\s*\}',
            # Slug pattern: "slug","value" or "slug":["value"]
            r'"(slug)"\s*[,:"]\s*"([^"]+)"',
        ]
        
        # Values to exclude (common RSC structural values)
        param_exclude = {
            # Next.js internal route segments
            'children', '__PAGE__', '__DEFAULT__', '__SLOT__',
            # Common structural values
            'default', 'null', 'undefined', 'true', 'false',
            # Layout segments (these are route names, not param values)
            'layout', 'page', 'loading', 'error', 'not-found',
        }
        
        # Structural keys that are not params
        structural_keys = {'children', 'parallelRouterKey', 'error', 'errorStyles', 
                          'template', 'notFound', 'forbidden', 'unauthorized'}
        
        for pattern in param_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    key, value = match[0], match[1]
                elif isinstance(match, str):
                    key, value = 'id', match
                else:
                    continue
                
                # Filter out structural RSC values
                if not value or value.startswith('/'):
                    continue
                if key.lower() in param_exclude or value.lower() in param_exclude:
                    continue
                if key in structural_keys:
                    continue
                # Skip if value looks like a route segment name (lowercase, no special chars, short)
                if re.match(r'^[a-z-]+$', value) and len(value) < 20:
                    continue
                    
                result['route_params'][key] = value
    
    @classmethod
    def _extract_route_tree(cls, content, result):
        """Extract route structure from RSC payload"""
        # Pattern 1: From chunk paths like app/users/[userId]/settings/page-xxx.js
        chunk_route_pattern = re.compile(r'app/([\w%\[\]/-]+)/(?:page|layout|loading|error|not-found)-[a-f0-9]+\.js')
        for match in chunk_route_pattern.finditer(content):
            route_path = match.group(1)
            # Decode URL encoding
            route_path = route_path.replace('%5B', '[').replace('%5D', ']')
            # Convert [param] to :param
            route_path = re.sub(r'\[([^\]]+)\]', r':\1', route_path)
            full_route = '/' + route_path
            if full_route not in result['route_tree'] and len(full_route) > 1:
                result['route_tree'].append(full_route)
        
        # Pattern 2: From RSC tree structure ["children","segment","children",...]
        tree_pattern = re.compile(r'\["children"\s*,\s*"([a-zA-Z0-9_-]+)"\s*,\s*"children"')
        segments = tree_pattern.findall(content)
        if segments:
            route_parts = [seg for seg in segments if seg not in ('__PAGE__', '__DEFAULT__', '__SLOT__')]
            if route_parts:
                inferred_route = '/' + '/'.join(route_parts)
                if inferred_route not in result['route_tree']:
                    result['route_tree'].append(inferred_route)
        
        # Pattern 3: Direct route segment arrays ["children", "segment", "children", ["paramName", "value", "d"], ...]
        dynamic_route_pattern = re.compile(
            r'\["children"\s*,\s*"([^"]+)"\s*,\s*"children"\s*,\s*\["([^"]+)"\s*,\s*"[^"]+"\s*,\s*"d"\]'
        )
        for match in dynamic_route_pattern.finditer(content):
            base_segment = match.group(1)
            param_name = match.group(2)
            route = '/%s/:%s' % (base_segment, param_name)
            if route not in result['route_tree']:
                result['route_tree'].append(route)
    
    @classmethod
    def _extract_params_from_structure(cls, data, result, prefix=''):
        """Recursively extract params from parsed structures"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and key.lower().endswith('id'):
                    result['route_params'][key] = value
                elif key in ['params', 'searchParams', 'query']:
                    if isinstance(value, dict):
                        result['route_params'].update(value)
                else:
                    cls._extract_params_from_structure(value, result, prefix + key + '.')
        elif isinstance(data, list):
            for item in data:
                cls._extract_params_from_structure(item, result, prefix)
    
    @classmethod
    def _parse_inline_content(cls, line, result):
        """Parse content that doesn't follow ID: format"""
        chunks = cls.CHUNK_PATH_PATTERN.findall(line)
        result['chunks'].extend(chunks)
    
    @classmethod
    def _extract_metadata(cls, result):
        """Extract page metadata from parsed structures"""
        for ds in result['data_structures']:
            data = ds.get('data', {})
            cls._find_metadata_recursive(data, result['metadata'])
    
    @classmethod
    def _find_metadata_recursive(cls, data, metadata):
        """Recursively find metadata in structures"""
        if isinstance(data, dict):
            if 'metadata' in data:
                if isinstance(data['metadata'], dict):
                    metadata.update(data['metadata'])
            for key in ['title', 'description', 'og:title', 'og:description']:
                if key in data:
                    metadata[key] = data[key]
            for value in data.values():
                cls._find_metadata_recursive(value, metadata)
        elif isinstance(data, list):
            for item in data:
                cls._find_metadata_recursive(item, metadata)
                # Check for meta tag patterns ["$","meta",null,{...}]
                if isinstance(item, list) and len(item) >= 4:
                    if item[0] == '__SYMBOL_$__' or item[0] == '$':
                        if item[1] == 'meta' and isinstance(item[3], dict):
                            props = item[3]
                            if 'name' in props and 'content' in props:
                                metadata[props['name']] = props['content']
                            elif 'property' in props and 'content' in props:
                                metadata[props['property']] = props['content']
    
    @classmethod
    def _parse_flight_manifest(cls, result):
        """Parse the flight manifest (usually line 0) for prefetched data"""
        # Line 0 typically contains: {"b":"buildId","f":[flight data...]}
        if '0' not in result['lines']:
            return

        line_0 = result['lines']['0']
        try:
            # Try to parse as JSON
            manifest = json.loads(line_0)
            result['flight_manifest'] = manifest

            # Extract build ID
            if 'b' in manifest:
                result['flight_manifest']['_build_id'] = manifest['b']

            # Parse the flight data array 'f' for route params and data
            if 'f' in manifest and isinstance(manifest['f'], list):
                cls._parse_flight_data(manifest['f'], result)
                # Also do a dedicated route param extraction pass
                cls._extract_route_params_from_flight(manifest['f'], result)

            # Parse 'S' field (often contains important refs)
            if 'S' in manifest:
                result['flight_manifest']['_stream_refs'] = manifest['S']

        except (ValueError, TypeError):
            # Not JSON or malformed - try to extract what we can
            cls._extract_data_from_raw(line_0, result)

    @classmethod
    def _extract_route_params_from_flight(cls, data, result):
        """Extract route parameters from flight manifest structure"""
        if isinstance(data, list):
            # Check for dynamic route segment: ["paramName", "value", "d"]
            if (len(data) == 3 and
                isinstance(data[0], str) and
                isinstance(data[1], str) and
                data[2] == 'd'):
                param_name = data[0]
                param_value = data[1]
                # Skip internal segments
                if param_name not in ('__PAGE__', '__DEFAULT__', '__SLOT__', 'children'):
                    result['route_params'][param_name] = param_value
            else:
                # Recurse into array
                for item in data:
                    cls._extract_route_params_from_flight(item, result)
        elif isinstance(data, dict):
            # Check for params object: {"params": {"key": "value"}}
            if 'params' in data and isinstance(data['params'], dict):
                for key, value in data['params'].items():
                    if isinstance(value, str) and key not in result['route_params']:
                        result['route_params'][key] = value
            # Check for searchParams
            if 'searchParams' in data and isinstance(data['searchParams'], dict):
                for key, value in data['searchParams'].items():
                    if isinstance(value, str):
                        result['route_params']['searchParam:' + key] = value
            # Recurse into dict values
            for value in data.values():
                cls._extract_route_params_from_flight(value, result)

    @classmethod
    def _parse_flight_data(cls, flight_data, result, path='root'):
        """Recursively parse flight data array for interesting values"""
        if not isinstance(flight_data, list):
            return

        for i, item in enumerate(flight_data):
            current_path = '%s[%d]' % (path, i)

            if isinstance(item, dict):
                # Check for data objects with interesting keys
                cls._extract_data_object(item, result, current_path)
            elif isinstance(item, list):
                # Check for React element structure ["$", "type", key, props, ...]
                if len(item) >= 4 and item[0] == '$':
                    cls._parse_react_element(item, result, current_path)
                else:
                    cls._parse_flight_data(item, result, current_path)
            elif isinstance(item, str):
                # Check for references
                if item.startswith('$L'):
                    # Lazy reference - will be resolved later
                    pass
                elif item.startswith('$F'):
                    # Server action reference
                    result['server_actions'].append({
                        'id': item[2:],
                        'path': current_path,
                        'type': 'flight_data'
                    })

    @classmethod
    def _parse_react_element(cls, element, result, path):
        """Parse a React element array: ["$", "type", key, props, ...children]"""
        if len(element) < 4:
            return

        elem_type = element[1] if len(element) > 1 else None
        elem_key = element[2] if len(element) > 2 else None
        elem_props = element[3] if len(element) > 3 else None

        # Skip internal React types
        if elem_type and isinstance(elem_type, str):
            if elem_type.startswith('$'):
                # Reference to another line/component
                ref_id = elem_type[2:] if elem_type.startswith('$L') else elem_type[1:]
                if ref_id in result['components']:
                    # Link props to component
                    if elem_props and isinstance(elem_props, dict):
                        comp_name = result['components'].get(ref_id, {})
                        if isinstance(comp_name, str):
                            result['component_props'][comp_name] = elem_props

            # Extract props if they contain data
            if elem_props and isinstance(elem_props, dict):
                cls._extract_data_object(elem_props, result, path + '.props')

        # Process children (elements 4+)
        for i, child in enumerate(element[4:]):
            if isinstance(child, list):
                if len(child) >= 4 and child[0] == '$':
                    cls._parse_react_element(child, result, '%s.children[%d]' % (path, i))
                else:
                    cls._parse_flight_data(child, result, '%s.children[%d]' % (path, i))

    # Keys that are React/HTML structural noise - never interesting
    NOISE_KEYS = frozenset([
        'className', 'classname', 'class', 'style', 'children', 'key', 'ref',
        'xmlns', 'viewBox', 'viewbox', 'fill', 'stroke', 'strokeWidth', 'strokewidth',
        'strokeLinecap', 'strokeLinejoin', 'strokeMiterlimit', 'd', 'points', 'cx', 'cy',
        'r', 'rx', 'ry', 'x', 'y', 'x1', 'x2', 'y1', 'y2', 'width', 'height',
        'transform', 'clipPath', 'clippath', 'clipRule', 'fillRule', 'fillOpacity',
        'strokeOpacity', 'opacity', 'gradientUnits', 'gradientTransform',
        'aria-hidden', 'aria-label', 'aria-labelledby', 'aria-describedby',
        'role', 'tabIndex', 'tabindex', 'disabled', 'hidden', 'lang', 'dir',
        'onClick', 'onSubmit', 'onChange', 'onBlur', 'onFocus', 'onKeyDown',
        'htmlFor', 'autoComplete', 'autoFocus', 'placeholder', 'maxLength', 'minLength',
        'dangerouslySetInnerHTML', 'suppressHydrationWarning',
        'precedence', 'crossOrigin', 'nonce', 'rel', 'as', 'media', 'integrity',
    ])

    # Keys that look like noise patterns (SVG, React, HTML)
    NOISE_PATTERNS = [
        r'^on[A-Z]',       # onClick, onChange, etc.
        r'^aria-',        # ARIA attributes
        r'^data-',        # data attributes (usually not sensitive)
        r'^stroke',       # SVG stroke props
        r'^fill',         # SVG fill props
        r'^clip',         # SVG clip props
    ]

    @classmethod
    def _is_noise_key(cls, key):
        """Check if a key is React/HTML structural noise"""
        if key in cls.NOISE_KEYS:
            return True
        for pattern in cls.NOISE_PATTERNS:
            if re.match(pattern, key):
                return True
        return False

    @classmethod
    def _extract_data_object(cls, obj, result, path):
        """Extract interesting data from an object"""
        if not isinstance(obj, dict):
            return

        # Filter out noise keys first
        interesting_keys = [k for k in obj.keys() if not cls._is_noise_key(k)]

        # If all keys are noise, skip this object entirely
        if not interesting_keys:
            return

        # Sensitive KEY patterns - the key name itself suggests sensitive data
        sensitive_key_patterns = [
            'password', 'passwd', 'pwd',
            'secret', 'token', 'apikey', 'api_key',
            'auth', 'session', 'sessionid', 'session_id',
            'credential', 'private', 'privatekey', 'private_key',
            'access_token', 'refresh_token', 'bearer',
            'ssn', 'social_security', 'credit_card', 'creditcard', 'cvv', 'ccv',
        ]

        # We don't try to guess "interesting" keys anymore - just show objects
        # that have real data values (not just React structure)

        # Check for sensitive VALUES (patterns in the actual data)
        sensitive_value_patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'email'),  # Email
            (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'jwt'),  # JWT
            (r'sk_live_[a-zA-Z0-9]{24,}', 'stripe_key'),  # Stripe secret
            (r'pk_live_[a-zA-Z0-9]{24,}', 'stripe_pub'),  # Stripe public
            (r'ghp_[a-zA-Z0-9]{36}', 'github_token'),  # GitHub token
            (r'xox[baprs]-[a-zA-Z0-9-]+', 'slack_token'),  # Slack token
            (r'AKIA[0-9A-Z]{16}', 'aws_key'),  # AWS access key
            (r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b', 'ssn'),  # SSN
            (r'\b[0-9]{13,16}\b', 'card_number'),  # Credit card (basic)
        ]

        is_sensitive = False
        sensitivity_reasons = []
        has_real_values = False

        for key in interesting_keys:
            key_lower = key.lower()
            value = obj.get(key)

            # Check if KEY name is sensitive
            for pattern in sensitive_key_patterns:
                if pattern in key_lower:
                    is_sensitive = True
                    sensitivity_reasons.append('key:%s' % key)
                    break

            # Check if VALUE contains sensitive patterns
            if isinstance(value, str) and len(value) > 5:
                for pattern, pattern_name in sensitive_value_patterns:
                    if re.search(pattern, value):
                        is_sensitive = True
                        sensitivity_reasons.append('value:%s(%s)' % (key, pattern_name))
                        break

            # Check if this object has actual data values (not just structure)
            if isinstance(value, str) and len(value) > 0 and not cls._is_noise_text(value):
                has_real_values = True
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                has_real_values = True
            elif isinstance(value, bool):
                has_real_values = True

        # Only add if sensitive OR has real non-empty values
        if is_sensitive or has_real_values:
            exposed_item = {
                'path': path,
                'data': {k: v for k, v in obj.items() if k in interesting_keys},  # Only non-noise
                'is_sensitive': is_sensitive,
                'keys': interesting_keys,
                'reasons': sensitivity_reasons if sensitivity_reasons else None
            }
            result['exposed_data'].append(exposed_item)

        # Recurse into nested objects (but skip children arrays which are usually React elements)
        for key, value in obj.items():
            if key == 'children':
                continue  # Skip React children - they're element trees not data
            if isinstance(value, dict):
                cls._extract_data_object(value, result, '%s.%s' % (path, key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        cls._extract_data_object(item, result, '%s.%s[%d]' % (path, key, i))

    @classmethod
    def _extract_data_from_raw(cls, content, result):
        """Extract data patterns from raw content when JSON parsing fails"""
        # Look for JSON-like objects embedded in the content
        # Pattern: {"key":"value",...}
        obj_pattern = re.compile(r'\{[^{}]*"[a-zA-Z_][a-zA-Z0-9_]*"\s*:\s*[^{}]+\}')
        matches = obj_pattern.findall(content)

        for match in matches[:20]:  # Limit to prevent explosion
            try:
                obj = json.loads(match)
                cls._extract_data_object(obj, result, 'raw_extract')
            except ValueError:
                pass

    # Patterns for text that is definitely noise (not user-visible content)
    TEXT_NOISE_PATTERNS = [
        r'^[\d.]+$',                    # Pure numbers
        r'^#[a-fA-F0-9]{3,8}$',         # Hex colors
        r'^rgba?\([^)]+\)$',            # RGB colors
        r'^data:',                      # Data URIs
        r'^M[\d\s,.-]+$',               # SVG path data
        r'^\$[A-Z]',                    # RSC references ($L, $F, etc)
        r'^__[A-Z]+__$',                # Internal markers
        r'^(true|false|null|undefined)$',  # JS literals
        r'^[a-z]{1,3}$',                # Very short strings (likely keys)
    ]
    # Note: URLs are NOT filtered - they can reveal staging/internal environments

    @classmethod
    def _is_noise_text(cls, text):
        """Check if text is technical noise rather than content"""
        if not text or len(text.strip()) < 2:
            return True
        text = text.strip()
        for pattern in cls.TEXT_NOISE_PATTERNS:
            if re.match(pattern, text):
                return True
        return False

    @classmethod
    def _extract_text_content(cls, data, result, path=''):
        """Extract ALL text content from React element trees"""
        if isinstance(data, str):
            text = data.strip()
            if not cls._is_noise_text(text):
                result.setdefault('text_content', []).append({
                    'path': path,
                    'text': text[:500]  # Allow longer text
                })
        elif isinstance(data, list):
            # Check for React element: ["$", "type", key, props, ...children]
            if len(data) >= 4 and data[0] == '$':
                # Extract text from children (positions 4+)
                for i, child in enumerate(data[4:]):
                    cls._extract_text_content(child, result, '%s.child[%d]' % (path, i))
                # Also check props.children
                props = data[3] if len(data) > 3 else None
                if isinstance(props, dict) and 'children' in props:
                    cls._extract_text_content(props['children'], result, path + '.children')
            else:
                for i, item in enumerate(data):
                    cls._extract_text_content(item, result, '%s[%d]' % (path, i))
        elif isinstance(data, dict):
            # Check for children prop
            if 'children' in data:
                cls._extract_text_content(data['children'], result, path + '.children')
            # Also check other string values that might be content
            for key, value in data.items():
                if key not in cls.NOISE_KEYS and isinstance(value, str):
                    if not cls._is_noise_text(value) and len(value) > 2:
                        # This might be content in a prop like "title", "label", "text"
                        result.setdefault('text_content', []).append({
                            'path': '%s.%s' % (path, key),
                            'text': value[:500]
                        })
                elif isinstance(value, (list, dict)):
                    cls._extract_text_content(value, result, '%s.%s' % (path, key))

    @classmethod
    def _extract_entity_arrays(cls, data, result, path=''):
        """Find arrays of objects that look like entity records"""
        if isinstance(data, list) and len(data) >= 2:
            # Check if this looks like an array of records
            obj_count = sum(1 for item in data if isinstance(item, dict))
            if obj_count >= 2:
                # Check if objects have similar structure (like DB records)
                keys_sets = [frozenset(item.keys()) for item in data if isinstance(item, dict)]
                if keys_sets:
                    # If most objects share keys, this is likely a record array
                    common_keys = keys_sets[0]
                    for ks in keys_sets[1:]:
                        common_keys = common_keys & ks

                    if len(common_keys) >= 2:
                        # This looks like entity records!
                        result.setdefault('entity_arrays', []).append({
                            'path': path,
                            'count': obj_count,
                            'common_keys': list(common_keys),
                            'sample': data[0] if data else None
                        })
                        # Also extract each record as exposed data
                        for i, item in enumerate(data):
                            if isinstance(item, dict):
                                cls._extract_data_object(item, result, '%s[%d]' % (path, i))
                        return  # Don't recurse further for this array

        # Recurse
        if isinstance(data, list):
            for i, item in enumerate(data):
                cls._extract_entity_arrays(item, result, '%s[%d]' % (path, i))
        elif isinstance(data, dict):
            for key, value in data.items():
                cls._extract_entity_arrays(value, result, '%s.%s' % (path, key))

    @classmethod
    def _resolve_references(cls, result):
        """Resolve $L references to build component tree with props"""
        lines = result['lines']
        references = result['references']

        # Build a map of line_id -> parsed content
        resolved = {}

        for line_id, content in lines.items():
            # Try to parse the content
            try:
                # Clean up RSC-specific syntax for parsing
                cleaned = content
                cleaned = re.sub(r'\$L([0-9a-fA-F]+)', r'"__REF_\1__"', cleaned)
                cleaned = cleaned.replace('$undefined', 'null')
                cleaned = re.sub(r'\$S([a-zA-Z.]+)', r'"__SYMBOL_\1__"', cleaned)
                cleaned = re.sub(r'\$F([0-9a-fA-F]+)', r'"__ACTION_\1__"', cleaned)

                if cleaned.startswith('{') or cleaned.startswith('['):
                    parsed = json.loads(cleaned)
                    resolved[line_id] = parsed

                    # Extract component props from parsed structure
                    cls._extract_props_from_resolved(parsed, line_id, result)

            except (ValueError, TypeError):
                pass

        result['resolved_tree'] = resolved

        # Now try to link components to their props
        cls._link_components_to_props(result)

    @classmethod
    def _extract_props_from_resolved(cls, data, line_id, result):
        """Extract props from resolved structures"""
        if isinstance(data, list) and len(data) >= 4:
            # Might be React element ["$", "type", key, props]
            if data[0] in ['$', '__SYMBOL_$__']:
                elem_type = data[1]
                props = data[3] if len(data) > 3 else None

                if props and isinstance(props, dict):
                    # Store props with reference to the element type
                    type_name = str(elem_type)
                    if type_name.startswith('__REF_'):
                        # This references another line for the component
                        ref_id = type_name[6:-2]  # Extract ID from __REF_xxx__
                        result['component_props'][ref_id] = props
                        # Also extract any interesting data from props
                        cls._extract_data_object(props, result, 'line_%s.props' % line_id)

        elif isinstance(data, dict):
            cls._extract_data_object(data, result, 'line_%s' % line_id)

        # Recurse
        if isinstance(data, list):
            for item in data:
                cls._extract_props_from_resolved(item, line_id, result)
        elif isinstance(data, dict):
            for value in data.values():
                cls._extract_props_from_resolved(value, line_id, result)

    @classmethod
    def _link_components_to_props(cls, result):
        """Link component names to their props based on references"""
        # Map component names to their line IDs
        comp_to_line = {}
        for name, info in result['components'].items():
            if isinstance(info, dict) and 'line_id' in info:
                comp_to_line[name] = info['line_id']

        # Try to match props from component_props
        for ref_id, props in list(result['component_props'].items()):
            # Find if this ref_id maps to a known component
            for line_id, content in result['lines'].items():
                if ref_id == line_id and content.startswith('I['):
                    # This is a component import line
                    # Extract component name
                    quoted = re.findall(r'"([^"]+)"', content)
                    if quoted:
                        comp_name = quoted[-1]
                        if comp_name in result['components']:
                            result['components'][comp_name]['props'] = props

    @classmethod
    def _extract_exposed_data(cls, result):
        """Final pass to consolidate and dedupe exposed data"""
        # Deduplicate exposed data
        seen = set()
        unique_exposed = []

        for item in result['exposed_data']:
            # Create a hashable key
            key = json.dumps(item['data'], sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                unique_exposed.append(item)

        result['exposed_data'] = unique_exposed

        # Sort by sensitivity
        result['exposed_data'].sort(key=lambda x: (not x.get('is_sensitive', False), x.get('path', '')))
    
    @classmethod
    def pretty_print(cls, parsed, include_raw=False):
        """Generate human-readable output"""
        output = []
        output.append("=" * 60)
        output.append("NEXT.JS RSC PARSED RESPONSE")
        output.append("=" * 60)

        # Build ID (useful for cache busting analysis)
        manifest = parsed.get('flight_manifest', {})
        if manifest.get('_build_id'):
            output.append("\n[BUILD ID]")
            output.append("  %s" % manifest['_build_id'])

        output.append("\n[ROUTE STRUCTURE]")
        if parsed.get('route_tree'):
            for route in parsed['route_tree']:
                output.append("  %s" % route)
        else:
            output.append("  (none detected)")

        output.append("\n[ROUTE PARAMETERS]")
        if parsed['route_params']:
            for key, value in sorted(parsed['route_params'].items()):
                output.append("  %s = %s" % (key, value))
        else:
            output.append("  (none detected)")

        # Entity arrays
        entity_arrays = parsed.get('entity_arrays', [])
        if entity_arrays:
            output.append("\n[ENTITY ARRAYS] (%d found)" % len(entity_arrays))
            output.append("  (Arrays of records - likely database entities)")
            for arr in entity_arrays[:5]:
                output.append("\n  Path: %s" % arr.get('path', '?'))
                output.append("  Count: %d records" % arr.get('count', 0))
                output.append("  Keys: %s" % ', '.join(arr.get('common_keys', [])))
                sample = arr.get('sample', {})
                if sample:
                    output.append("  Sample:")
                    sample_str = json.dumps(sample, indent=4, default=str)
                    for line in sample_str.split('\n')[:12]:
                        output.append("    %s" % line)
                    if len(sample_str.split('\n')) > 12:
                        output.append("    ...")

        # EXPOSED DATA - The good stuff for security
        exposed = parsed.get('exposed_data', [])
        sensitive = [e for e in exposed if e.get('is_sensitive')]
        nonsensitive = [e for e in exposed if not e.get('is_sensitive')]

        if sensitive:
            output.append("\n" + "!" * 60)
            output.append("[INTERESTING DATA] (%d items)" % len(sensitive))
            output.append("!" * 60)
            for item in sensitive[:10]:
                output.append("\n  Path: %s" % item.get('path', 'unknown'))
                reasons = item.get('reasons', [])
                if reasons:
                    output.append("  WHY: %s" % ', '.join(reasons))
                output.append("  Keys: %s" % ', '.join(item.get('keys', [])))
                data_str = json.dumps(item.get('data', {}), indent=4, default=str)
                for line in data_str.split('\n')[:15]:
                    output.append("    %s" % line)
                if len(data_str.split('\n')) > 15:
                    output.append("    ...")
            if len(sensitive) > 10:
                output.append("\n  ... and %d more sensitive items" % (len(sensitive) - 10))

        if nonsensitive:
            output.append("\n[EXPOSED DATA] (%d items)" % len(nonsensitive))
            for item in nonsensitive[:8]:
                output.append("\n  Path: %s" % item.get('path', 'unknown'))
                output.append("  Keys: %s" % ', '.join(item.get('keys', [])))
                data_str = json.dumps(item.get('data', {}), indent=4, default=str)
                for line in data_str.split('\n')[:8]:
                    output.append("    %s" % line)
                if len(data_str.split('\n')) > 8:
                    output.append("    ...")
            if len(nonsensitive) > 8:
                output.append("\n  ... and %d more data items" % (len(nonsensitive) - 8))

        # Server Actions - important for security testing
        server_actions = parsed.get('server_actions', [])
        if server_actions:
            output.append("\n[SERVER ACTIONS] (%d found)" % len(server_actions))
            output.append("  (These are server-side functions callable from client)")
            seen_ids = set()
            for action in server_actions:
                action_id = action.get('id', '')
                if action_id not in seen_ids:
                    seen_ids.add(action_id)
                    output.append("  $F%s - %s" % (action_id, action.get('path', action.get('found_in_line', ''))))

        # Component Props - data passed to components
        comp_props = parsed.get('component_props', {})
        if comp_props:
            output.append("\n[COMPONENT PROPS]")
            for ref_id, props in list(comp_props.items())[:10]:
                if isinstance(props, dict) and props:
                    output.append("  [Ref %s]" % ref_id)
                    props_str = json.dumps(props, indent=4, default=str)
                    for line in props_str.split('\n')[:6]:
                        output.append("    %s" % line)
                    if len(props_str.split('\n')) > 6:
                        output.append("    ...")

        output.append("\n[METADATA]")
        if parsed['metadata']:
            for key, value in sorted(parsed['metadata'].items()):
                val_str = str(value)[:80] + "..." if len(str(value)) > 80 else str(value)
                output.append("  %s: %s" % (key, val_str))
        else:
            output.append("  (none detected)")

        # Text content - actual strings rendered on page
        text_content = parsed.get('text_content', [])
        # Dedupe and filter
        seen_texts = set()
        unique_texts = []
        for tc in text_content:
            text = tc.get('text', '')
            if text not in seen_texts and len(text) > 3:
                seen_texts.add(text)
                unique_texts.append(tc)
        if unique_texts:
            output.append("\n[TEXT CONTENT] (%d unique strings)" % len(unique_texts))
            for tc in unique_texts[:20]:
                text = tc.get('text', '')
                if len(text) > 80:
                    text = text[:80] + '...'
                output.append("  \"%s\"" % text)
            if len(unique_texts) > 20:
                output.append("  ... and %d more" % (len(unique_texts) - 20))

        # Data structures - filter out boring meta/viewport stuff
        interesting_structures = []
        for ds in parsed.get('data_structures', []):
            data = ds.get('data', {})
            # Skip if it's just meta tags
            data_str = json.dumps(data, default=str)
            if '"charSet"' in data_str and len(data_str) < 200:
                continue
            if '"viewport"' in data_str and '"meta"' in data_str and len(data_str) < 300:
                continue
            interesting_structures.append(ds)

        if interesting_structures:
            output.append("\n[DATA STRUCTURES] (%d found)" % len(interesting_structures))
            for ds in interesting_structures[:5]:
                output.append("  [Line %s]" % ds.get('line_id', '?'))
                data_str = json.dumps(ds.get('data', {}), indent=4, default=str)
                for line in data_str.split('\n')[:10]:
                    output.append("    %s" % line)
                if len(data_str.split('\n')) > 10:
                    output.append("    ...")

        # Components at bottom (lower priority)
        components = parsed.get('components', {})
        visible_components = [n for n in components.keys() if not n.startswith('_')]
        if visible_components:
            output.append("\n[COMPONENTS] (%d found)" % len(visible_components))
            for name in sorted(visible_components):
                output.append("  - %s" % name)

        if include_raw:
            output.append("\n[RAW LINES] (%d total)" % parsed['raw_line_count'])
            for line_id, content in sorted(parsed['lines'].items(), key=lambda x: int(x[0], 16) if all(c in '0123456789abcdefABCDEF' for c in x[0]) else 0):
                output.append("  %s: %s" % (line_id, content[:100]))

        return '\n'.join(output)


class RSCEditorTab(IMessageEditorTab):
    """Custom tab for RSC responses in Burp message editor"""
    
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._controller = controller
        self._editable = editable
        
        # Build UI
        self._panel = JPanel(BorderLayout())
        
        # Tabbed pane for different views
        self._tabs = JTabbedPane()
        
        # Pretty view
        self._pretty_area = JTextArea()
        self._pretty_area.setEditable(False)
        self._pretty_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._pretty_area.setLineWrap(True)
        self._tabs.addTab("Parsed", JScrollPane(self._pretty_area))
        
        # Components tree view
        self._tree_root = DefaultMutableTreeNode("RSC Response")
        self._tree = JTree(self._tree_root)
        self._tabs.addTab("Tree", JScrollPane(self._tree))
        
        # Raw JSON view
        self._json_area = JTextArea()
        self._json_area.setEditable(False)
        self._json_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._tabs.addTab("JSON", JScrollPane(self._json_area))
        
        # Security findings
        self._security_area = JTextArea()
        self._security_area.setEditable(False)
        self._security_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._security_area.setForeground(Color(200, 50, 50))
        self._tabs.addTab("Security", JScrollPane(self._security_area))
        
        self._panel.add(self._tabs, BorderLayout.CENTER)
        
        self._current_message = None
    
    def getTabCaption(self):
        return "RSC Parsed"
    
    def getUiComponent(self):
        return self._panel
    
    def isEnabled(self, content, isRequest):
        if isRequest:
            return False
        
        # Check if RSC response
        return self._extender._is_rsc_response(content)
    
    def setMessage(self, content, isRequest):
        if content is None:
            self._pretty_area.setText("")
            self._json_area.setText("")
            self._security_area.setText("")
            return
        
        self._current_message = content
        
        # Parse the RSC content
        body = self._extender._get_response_body(content)
        parsed = RSCParser.parse(body)
        
        # Update pretty view
        self._pretty_area.setText(RSCParser.pretty_print(parsed, include_raw=True))
        self._pretty_area.setCaretPosition(0)
        
        # Update JSON view
        self._json_area.setText(json.dumps(parsed, indent=2, default=str))
        self._json_area.setCaretPosition(0)
        
        # Update tree view
        self._update_tree(parsed)
        
        # Update security view
        self._update_security_view(parsed)
    
    def _update_tree(self, parsed):
        """Build tree view of RSC structure"""
        self._tree_root.removeAllChildren()

        # Update root node with route info
        routes = parsed.get('route_tree', [])
        if routes:
            self._tree_root.setUserObject("RSC: %s" % routes[0])
        else:
            self._tree_root.setUserObject("RSC Response")

        # Exposed Data (sensitive first)
        exposed = parsed.get('exposed_data', [])
        sensitive = [e for e in exposed if e.get('is_sensitive')]
        if sensitive:
            sensitive_node = DefaultMutableTreeNode("!! SENSITIVE DATA (%d)" % len(sensitive))
            for item in sensitive[:20]:
                item_node = DefaultMutableTreeNode(item.get('path', 'unknown'))
                for key in item.get('keys', []):
                    item_node.add(DefaultMutableTreeNode(key))
                sensitive_node.add(item_node)
            self._tree_root.add(sensitive_node)

        # Entity Arrays
        entity_arrays = parsed.get('entity_arrays', [])
        if entity_arrays:
            entities_node = DefaultMutableTreeNode("!! Entity Arrays (%d)" % len(entity_arrays))
            for arr in entity_arrays[:10]:
                arr_node = DefaultMutableTreeNode("%s (%d records)" % (arr.get('path', '?'), arr.get('count', 0)))
                for key in arr.get('common_keys', [])[:10]:
                    arr_node.add(DefaultMutableTreeNode(key))
                entities_node.add(arr_node)
            self._tree_root.add(entities_node)

        # Server Actions
        server_actions = parsed.get('server_actions', [])
        if server_actions:
            actions_node = DefaultMutableTreeNode("Server Actions (%d)" % len(server_actions))
            seen = set()
            for action in server_actions:
                action_id = action.get('id', '')
                if action_id not in seen:
                    seen.add(action_id)
                    actions_node.add(DefaultMutableTreeNode("$F%s" % action_id))
            self._tree_root.add(actions_node)

        # Route structure
        route_tree = parsed.get('route_tree', [])
        if route_tree:
            routes_node = DefaultMutableTreeNode("Route Structure (%d)" % len(route_tree))
            for route in route_tree:
                routes_node.add(DefaultMutableTreeNode(route))
            self._tree_root.add(routes_node)

        # Route params
        route_params = parsed.get('route_params', {})
        if route_params:
            params_node = DefaultMutableTreeNode("Route Parameters (%d)" % len(route_params))
            for key, value in route_params.items():
                params_node.add(DefaultMutableTreeNode("%s = %s" % (key, value)))
            self._tree_root.add(params_node)

        # Component Props
        comp_props = parsed.get('component_props', {})
        if comp_props:
            props_node = DefaultMutableTreeNode("Component Props")
            for ref_id, props in list(comp_props.items())[:15]:
                if isinstance(props, dict) and props:
                    ref_node = DefaultMutableTreeNode("Ref %s" % ref_id)
                    for key in list(props.keys())[:10]:
                        value = props[key]
                        val_str = str(value)[:50] if value else 'null'
                        ref_node.add(DefaultMutableTreeNode("%s: %s" % (key, val_str)))
                    props_node.add(ref_node)
            self._tree_root.add(props_node)

        # Non-sensitive exposed data
        nonsensitive = [e for e in exposed if not e.get('is_sensitive')]
        if nonsensitive:
            data_node = DefaultMutableTreeNode("Exposed Data (%d)" % len(nonsensitive))
            for item in nonsensitive[:15]:
                item_node = DefaultMutableTreeNode(item.get('path', 'unknown'))
                for key in item.get('keys', [])[:8]:
                    item_node.add(DefaultMutableTreeNode(key))
                data_node.add(item_node)
            self._tree_root.add(data_node)

        # Text Content
        text_content = parsed.get('text_content', [])
        seen_texts = set()
        unique_texts = []
        for tc in text_content:
            text = tc.get('text', '')
            if text not in seen_texts and len(text) > 3:
                seen_texts.add(text)
                unique_texts.append(text)
        if unique_texts:
            text_node = DefaultMutableTreeNode("Text Content (%d)" % len(unique_texts))
            for text in unique_texts[:30]:
                display_text = text[:60] + '...' if len(text) > 60 else text
                text_node.add(DefaultMutableTreeNode('"%s"' % display_text))
            self._tree_root.add(text_node)

        # Components (at bottom, lower priority)
        components = parsed.get('components', {})
        visible_components = [n for n in components.keys() if not n.startswith('_')]
        if visible_components:
            comp_node = DefaultMutableTreeNode("Components (%d)" % len(visible_components))
            for name in sorted(visible_components)[:30]:
                comp_node.add(DefaultMutableTreeNode(name))
            self._tree_root.add(comp_node)

        # Refresh tree
        self._tree.updateUI()
    
    def _update_security_view(self, parsed):
        """Generate security-focused analysis"""
        findings = []
        findings.append("SECURITY ANALYSIS")
        findings.append("=" * 50)

        # EXPOSED DATA - Most important for security
        exposed = parsed.get('exposed_data', [])
        sensitive = [e for e in exposed if e.get('is_sensitive')]

        if sensitive:
            findings.append("\n" + "!" * 50)
            findings.append("[!!!] INTERESTING DATA (%d items)" % len(sensitive))
            findings.append("!" * 50)
            for item in sensitive[:15]:
                findings.append("\n    Path: %s" % item.get('path', 'unknown'))
                reasons = item.get('reasons', [])
                if reasons:
                    findings.append("    WHY FLAGGED: %s" % ', '.join(reasons))
                findings.append("    Keys: %s" % ', '.join(item.get('keys', [])))
                data_str = json.dumps(item.get('data', {}), indent=4, default=str)
                for line in data_str.split('\n')[:12]:
                    findings.append("      %s" % line)
                if len(data_str.split('\n')) > 12:
                    findings.append("      ...")

        # Entity Arrays - lists of records (database entities)
        entity_arrays = parsed.get('entity_arrays', [])
        if entity_arrays:
            findings.append("\n[!] ENTITY ARRAYS DETECTED (%d)" % len(entity_arrays))
            findings.append("    Arrays of database records exposed in response!")
            for arr in entity_arrays[:5]:
                findings.append("\n    Path: %s" % arr.get('path', '?'))
                findings.append("    Records: %d" % arr.get('count', 0))
                findings.append("    Fields: %s" % ', '.join(arr.get('common_keys', [])))
                sample = arr.get('sample', {})
                if sample:
                    sample_str = json.dumps(sample, indent=4, default=str)
                    for line in sample_str.split('\n')[:8]:
                        findings.append("      %s" % line)
                    if len(sample_str.split('\n')) > 8:
                        findings.append("      ...")

        # Server Actions - RPC attack surface
        server_actions = parsed.get('server_actions', [])
        if server_actions:
            findings.append("\n[!] SERVER ACTIONS (%d found)" % len(server_actions))
            findings.append("    These are server functions callable from client!")
            findings.append("    Test for: auth bypass, IDOR, injection, mass assignment")
            seen_ids = set()
            for action in server_actions:
                action_id = action.get('id', '')
                if action_id not in seen_ids:
                    seen_ids.add(action_id)
                    findings.append("    $F%s" % action_id)

        # Route structure
        routes = parsed.get('route_tree', [])
        if routes:
            findings.append("\n[!] ROUTE STRUCTURE")
            for route in routes:
                findings.append("    %s" % route)

        # Check route parameters
        params = parsed.get('route_params', {})
        if params:
            findings.append("\n[!] ROUTE PARAMETERS (IDOR Targets)")
            for key, value in params.items():
                findings.append("    %s = %s" % (key, value))

                # Analyze ID format
                value_str = str(value)
                if re.match(r'^[0-9]+$', value_str):
                    if len(value_str) <= 10:
                        findings.append("    ^ CRITICAL: Sequential numeric ID - trivial enumeration")
                    else:
                        findings.append("    ^ HIGH: Large numeric ID - may still be sequential")
                elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-1[a-f0-9]{3}-', value_str, re.I):
                    findings.append("    ^ HIGH: UUID v1 - time-based, potentially predictable")
                elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-', value_str, re.I):
                    findings.append("    ^ LOW: UUID v4 - random, hard to enumerate")
                elif re.match(r'^[a-f0-9]{24}$', value_str, re.I):
                    findings.append("    ^ MEDIUM: MongoDB ObjectId - timestamp prefix may leak info")
                elif re.match(r'^[A-Za-z0-9]{20}$', value_str):
                    findings.append("    ^ LOW: Firestore-style ID - pseudo-random")
                elif len(value_str) >= 20:
                    findings.append("    ^ LOW: Long ID - likely random, but verify")

        # Component Props with data
        comp_props = parsed.get('component_props', {})
        interesting_props = {k: v for k, v in comp_props.items()
                           if isinstance(v, dict) and len(v) > 0}
        if interesting_props:
            findings.append("\n[!] COMPONENT PROPS (data passed to client)")
            for ref_id, props in list(interesting_props.items())[:8]:
                findings.append("    [Ref %s] keys: %s" % (ref_id, ', '.join(list(props.keys())[:5])))

        # Check for sensitive component names
        sensitive_patterns = [
            ('auth', 'Authentication logic exposed'),
            ('admin', 'Admin functionality visible'),
            ('role', 'Role-based access control'),
            ('permission', 'Permission system'),
            ('user', 'User data handling'),
            ('payment', 'Payment processing'),
            ('secret', 'Sensitive data'),
            ('private', 'Private data handling'),
            ('internal', 'Internal functionality'),
        ]

        components = parsed.get('components', {})
        flagged = []
        for name in components.keys():
            name_lower = name.lower()
            for pattern, desc in sensitive_patterns:
                if pattern in name_lower:
                    flagged.append((name, desc))
                    break

        if flagged:
            findings.append("\n[!] SENSITIVE COMPONENTS DETECTED")
            for name, desc in flagged:
                findings.append("    %s - %s" % (name, desc))

        # Other exposed data (non-sensitive)
        nonsensitive = [e for e in exposed if not e.get('is_sensitive')]
        if nonsensitive:
            findings.append("\n[*] OTHER EXPOSED DATA (%d items)" % len(nonsensitive))
            for item in nonsensitive[:5]:
                findings.append("    %s: %s" % (item.get('path', '?'), ', '.join(item.get('keys', [])[:5])))

        # Components at bottom (lower priority)
        if flagged:
            # Already showed sensitive components above
            pass
        else:
            components = parsed.get('components', {})
            if components:
                findings.append("\n[*] COMPONENTS (%d total)" % len(components))
                findings.append("    (No sensitive-looking component names detected)")

        self._security_area.setText('\n'.join(findings))
        self._security_area.setCaretPosition(0)
    
    def _find_sensitive_keys(self, data, prefix=''):
        """Find sensitive-looking keys in data structures"""
        sensitive = []
        sensitive_patterns = ['password', 'secret', 'token', 'key', 'auth', 'session', 
                            'credit', 'ssn', 'email', 'phone', 'address', 'private']
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = prefix + '.' + key if prefix else key
                key_lower = key.lower()
                for pattern in sensitive_patterns:
                    if pattern in key_lower:
                        sensitive.append(full_key)
                        break
                sensitive.extend(self._find_sensitive_keys(value, full_key))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                sensitive.extend(self._find_sensitive_keys(item, prefix + '[%d]' % i))
        
        return sensitive
    
    def getMessage(self):
        return self._current_message
    
    def isModified(self):
        return False
    
    def getSelectedData(self):
        return self._pretty_area.getSelectedText()