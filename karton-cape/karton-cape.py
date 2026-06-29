#!/usr/bin/env python3
"""
Karton CAPE Intelligence Plugin
==============================

Comprehensive CAPEv2 Sandbox integration for malware analysis pipelines.
Extracts full intelligence data including IOCs, TTPs, behavioral analysis, payloads, and configs.

Features:
- Complete data extraction from all CAPE report sections
- Structured output for downstream Karton processors
- Scalable batch processing with error handling
- IOC and TTP extraction for threat intelligence
- Payload and configuration extraction integration
- YARA signature and behavioral analysis

Author: Reverse Engineering Pipeline Team
Version: 1.0.0
"""

import os
import time
import json
import logging
import requests
from typing import Dict, List, Optional, Any

from karton.core import Karton, Task, Resource

log = logging.getLogger(__name__)

BEHAVIOR_IOC_LIMIT = 5

#NOTE recuperer une liste des machines depuis l'API ou hardcoder une liste de machines disponibles pour l'analyse
MACHINES_LIST = {'Windows': {
    'office': 'win-cape-office-cve',
    'win10': 'win10-cape',
}, 'linux': {
    'linux': 'linux-cape'} #NOTE existe pas mais au moins c'est la
    }

def remove_empty_values(data: Any) -> Any:
    """Recursively removes empty values from nested structures.

    This helper traverses dictionaries and lists and removes entries whose value
    is considered empty. Empty values are:
    - ``None``
    - empty strings
    - empty lists
    - empty dictionaries

    The original structure is not modified in place. A cleaned copy of the
    structure is returned.

    Args:
        data: Data structure to clean. Can be a dictionary, a list, or any
            scalar value.

    Returns:
        The same structure type with empty values removed recursively. Scalar
        values are returned unchanged.
    """
    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            cleaned_value = remove_empty_values(value)
            if cleaned_value in (None, "", [], {}):
                continue
            cleaned[key] = cleaned_value
        return cleaned

    if isinstance(data, list):
        cleaned = []
        for item in data:
            cleaned_item = remove_empty_values(item)
            if cleaned_item in (None, "", [], {}):
                continue
            cleaned.append(cleaned_item)
        return cleaned

    return data




class CapeKarton(Karton):
    """Karton service integrating CAPEv2 malware sandbox analysis.

    This Karton processor listens for recognized samples, submits them to a
    CAPE sandbox, waits for the analysis to finish, retrieves the generated
    report, extracts threat intelligence data, and forwards a consolidated
    analysis task to downstream Karton components.

    The class is responsible for:
    - determining whether a file should be analyzed by CAPE;
    - submitting a sample to the CAPE API;
    - polling CAPE until analysis completion or timeout;
    - retrieving the final CAPE report;
    - extracting IOCs, TTPs, signatures, payload metadata and process trees;
    - building a consolidated analysis report for Karton consumers;
    - producing an error report when the analysis cannot be completed.

    Attributes:
        identity (str): Karton service identity.
        filters (List[Dict[str, str]]): Karton filters used to subscribe to
            recognized sample tasks.
    """
    
    identity = "karton.cape"
    filters = [{"type": "sample", "stage": "recognized"}]
    
    def __init__(self, config=None):
        """Initialize the CAPE Karton service and its runtime configuration.

        The constructor loads CAPE-related settings from the Karton
        configuration, creates an HTTP session used to communicate with the
        CAPE API, initializes default analysis options, and defines the set of
        file extensions supported by the sandbox integration.

        Args:
            config: Karton configuration object passed to the base
                :class:`karton.core.Karton` class. If ``None``, the default
                Karton configuration loading behavior is used.
        """
        super().__init__(config=config)
        
        # CAPE API configuration
        self.api_url = self.config.get("cape", "api_url", fallback="http://cape-web:8000")
        self.api_token = self.config.get("cape", "api_token", fallback="")
        self.poll_interval = self.config.getint("cape", "poll_interval", fallback=30)
        self.max_wait_time = self.config.getint("cape", "max_wait_time", fallback=1800)  # 30 minutes
        
        
        # self.api_url_VT = self.config.get("VT", "api_url", fallback="API_KEYS")
        
        
        # Analysis options
        self.default_timeout = self.config.getint("cape", "timeout", fallback=300)
        self.default_package = self.config.get("cape", "package", fallback="exe")
        self.enable_screenshots = self.config.getboolean("cape", "screenshots", fallback=True)
        self.enable_procmon = self.config.getboolean("cape", "procmon", fallback=True)
        
        self.session = requests.Session()
        if self.api_token:
            self.session.headers.update({
                "Authorization": f"Token {self.api_token}"
            })
        
        # Supported file extensions for CAPE analysis
        self.supported_extensions = {
            '.exe', '.dll', '.sys', '.scr', '.com', '.pif',  # PE files
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',  # Office
            '.pdf',  # PDF files
            '.zip', '.rar', '.7z',  # Archives
            '.jar', '.apk',  # Java/Android
            '.ps1', '.bat', '.cmd', '.vbs', '.js',  # Scripts
            '.msi', '.cab',  # Installers
        }
        
        self.tags = ["karton:capeV2"]
        
        log.info(f"CAPE Karton initialized with API URL: {self.api_url}")
    
    def should_process_file(self, sample_name: str, file_size: int) -> bool:
        """Determine whether a sample is eligible for CAPE analysis.

        The decision is based on simple heuristics:
        - reject files larger than the configured sandbox limit threshold;
        - reject very small files unlikely to produce meaningful results;
        - accept files with an extension explicitly supported by CAPE;
        - optionally accept extensionless files if their size suggests they may
          still be executable or interesting for sandboxing.

        Args:
            sample_name: Original sample filename as received from Karton.
            file_size: Sample size in bytes.

        Returns:
            ``True`` if the file should be submitted to CAPE, otherwise
            ``False``.
        """       
        # Check file size (CAPE has limits)
        if file_size > 200 * 1024 * 1024:  # 200MB limit
            self.log.warning(f"File too large for CAPE: {file_size:,} bytes")
            return False
        
        if file_size < 100:  # Skip very small files
            self.log.info(f"File too small for meaningful analysis: {file_size} bytes")
            return False
        
        # Check file extension
        if sample_name:
            file_ext = os.path.splitext(sample_name.lower())[1]
            if file_ext in self.supported_extensions:
                self.log.info(f"File {sample_name} will be processed by CAPE (extension: {file_ext})")
                return True
        
        # For files without extensions, check if they might be executables
        if file_size > 1024:  # At least 1KB
            self.log.info(f"File {sample_name} will be processed by CAPE (no extension but reasonable size)")
            return True
        
        self.log.info(f"Skipping file {sample_name} - unsupported type or too small")
        return False
    
    def submit_sample(self, file_path: str, sample_name: str) -> Optional[int]:
        """Submit a sample file to the CAPE API.

        This method prepares the submission payload, selects an analysis package
        based on the sample extension when possible, uploads the file to the
        CAPE ``tasks/create/file`` endpoint, and extracts the returned task ID.

        Args:
            file_path: Local filesystem path of the sample to upload.
            sample_name: Original filename used for CAPE submission and package
                selection.

        Returns:
            The CAPE task identifier returned by the API if the submission
            succeeds, otherwise ``None``.
        """       
        try:
            # Prepare submission options
            options = {
                'timeout': self.default_timeout,
                'package': self.default_package,
                'options': {
                    'screenshots': self.enable_screenshots,
                    'procmon': self.enable_procmon,
                    'cape': True,  # Enable CAPE payload extraction
                    'extraction': True,  # Enable configuration extraction
                    'behavioral': True,  # Enable behavioral analysis
                },
                'machine': "Win10x64",
                #TODO mettre une options pour avoir un choix sur la VM & analysis memoire and more ...
            }
            
            # Auto-select package based on file extension
                
            if sample_name: #TODO mettre une options pour avoir un choix sur la VM
                file_ext = os.path.splitext(sample_name.lower())[1]
                if file_ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
                    options['package'] = 'doc'
                elif file_ext == '.pdf':
                    options['package'] = 'pdf'
                elif file_ext in ['.zip', '.rar', '.7z']:
                    options['package'] = 'archive'
                elif file_ext in ['.jar']:
                    options['package'] = 'jar'
                elif file_ext in ['.apk']:
                    options['package'] = 'apk'
                elif file_ext in ['.ps1', '.bat', '.cmd', '.vbs', '.js']:
                    options['package'] = 'script'
            
            # Prepare file for upload
            with open(file_path, 'rb') as f:
                files = {
                    'file': (sample_name or 'sample', f, 'application/octet-stream')
                }
                
                data = {
                    'timeout': options['timeout'],
                    'package': options['package'],
                    'options': json.dumps(options['options'])
                    #TODO mettre une options pour avoir un choix sur la VM
                }
                
                self.log.info(f"Submitting sample {sample_name} to CAPE with package: {options['package']}")
                
                response = self.session.post(
                    f"{self.api_url}/apiv2/tasks/create/file/",
                    files=files,
                    data=data, #TODO mettre une options pour avoir un choix sur la VM
                    timeout=60
                )
                response.raise_for_status()
                
                result = response.json()
                task_id = str(result['data'].get('task_ids')).split('[')[-1].split(']')[0] # full number and not [id] --> {"error":false,"data":{"task_ids":[31],"message":"Task ID 31 has been submitted"},"errors":[],"url":["http://example.tld/submit/status/31/"]}
                
                self.log.info(f"Details 1.0: Task ID {task_id}")
                self.log.info(f"Details 2.0: Task ID {str(result['data'].get('task_ids'))}")
                
                
                if task_id:
                    self.log.info(f"Sample submitted successfully: Task ID {task_id}")
                    return task_id
                else:
                    self.log.error(f"No task ID returned: {result}")
                    return None
                    
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error submitting sample: {e}")
            self.log.warning(f"CAPE service appears to be unavailable - skipping analysis")
            return None
        except Exception as e:
            self.log.error(f"Unexpected error submitting sample: {e}")
            return None
    
    def wait_for_analysis(self, task_id: int) -> bool:
        """Poll CAPE until the submitted analysis reaches a terminal state.

        The method repeatedly queries the CAPE ``tasks/view`` endpoint until
        one of the following conditions is met:
        - the analysis is reported successfully;
        - the analysis reaches a known failure state;
        - the maximum waiting time is exceeded.

        Args:
            task_id: CAPE task identifier to monitor.

        Returns:
            ``True`` if the task reaches the ``reported`` status, otherwise
            ``False``.
        """
        start_time = time.time()
        
        self.log.info(f"Waiting for analysis to complete for task {task_id}")
        
        while time.time() - start_time < self.max_wait_time: #tant que ça prend moins de 30min
            try:
                response = self.session.get(f"{self.api_url}/apiv2/tasks/view/{task_id}/")
                response.raise_for_status()
                
                task_info = response.json()
                status = task_info['data'].get('status')
                
                
                self.log.info(f"Task {task_id} status: {status}")
                
                
                if status == 'reported':
                    self.log.info(f"Analysis completed for task {task_id}")
                    return True
                elif status in ['failure', 'timeout', 'failed_analysis', 'failed_processing', 'failed_reporting']:
                    self.log.error(f"Analysis failed with status: {status}")
                    return False
                
                time.sleep(self.poll_interval)
                
            except requests.exceptions.RequestException as e:
                self.log.error(f"Error checking task status: {e}")
                time.sleep(self.poll_interval)
        
        self.log.warning(f"Analysis timeout for task {task_id}")
        return False
    
    def get_comprehensive_analysis_results(self, task_id: int) -> Dict[str, Any]:
        """Retrieve the full CAPE JSON report for a completed task.

        This method requests the report from CAPE and returns the raw JSON
        payload so that downstream extraction methods can work from the original
        report structure.

        Args:
            task_id: CAPE task identifier for which the report must be fetched.

        Returns:
            A dictionary representing the full CAPE report. If the report cannot
            be retrieved, an empty dictionary is returned.
        """      
        results = {}
        
        try:
            # Get main report
            report_response = self.session.get(f"{self.api_url}/apiv2/tasks/get/report/{task_id}/")
            if report_response.status_code != 200:
                self.log.warning(f"Failed to get main report: {report_response.status_code}")
                return results
            
            self.log.info(f"Retrieved main report for task {task_id}")
            
        except Exception as e:
            self.log.error(f"Error retrieving comprehensive analysis results: {e}")
        
        return report_response.json()
    
    def extract_iocs(self, report_data: Dict[str, Any])->List[List[Any]]:
        """Extract indicators of compromise from a CAPE report.

        The extraction currently consolidates indicators from multiple CAPE
        sections, including:
        - network domains, IPs, URLs and TCP flows;
        - behavioral process activity;
        - file and registry access operations;
        - mutexes;
        - dropped files and their hashes.

        Relationships between indicators are preserved when possible, for
        example domain-to-IP or IP-to-URL associations.

        Args:
            report_data: Raw CAPE report content.

        Returns:
            A nested structure containing the extracted IOCs grouped by type,
            such as domains, IPs, URLs, files, registries, mutexes, processes,
            dropped files and network flows. Empty values are removed from the
            final structure.
        """
        iocs = {
            "domains": {},
            "ips": {},
            "urls": {},
            "files": {},
            "registries": {},
            "mutexes": {},
            "processes": {},
            "dropped_files": {},
            "network_flows": []
        }
        
        # Extract from network section
        network = report_data.get('network', {})
        if isinstance(network, dict):
            # Domains associated to IPs when CAPE provides both.
            for domain in network.get('domains', []):
                if isinstance(domain, dict):
                    domain_name = domain.get('domain', '')
                    ip = domain.get('ip', '')
                else:
                    domain_name = str(domain)
                    ip = ''

                if not domain_name:
                    continue

                if domain_name not in iocs["domains"]:
                    iocs["domains"][domain_name] = {"ips": [], "urls": []}

                if ip and ip not in iocs["domains"][domain_name]["ips"]:
                    iocs["domains"][domain_name]["ips"].append(ip)

                if ip:
                    ip_entry = iocs["ips"].setdefault(
                        ip,
                        {"domains": [], "asn": "", "asn_name": "", "urls": [], "network_flows": []}
                    )
                    if domain_name not in ip_entry["domains"]:
                        ip_entry["domains"].append(domain_name)
            
            # IPs & ASNs
            for host in network.get('hosts', []):
                if isinstance(host, dict):
                    ip = host.get('ip', '')
                    if not ip:
                        continue

                    ip_entry = iocs["ips"].setdefault(
                        ip,
                        {"domains": [], "asn": "", "asn_name": "", "urls": [], "network_flows": []}
                    )
                    ip_entry["asn"] = host.get('asn', '')
                    ip_entry["asn_name"] = host.get('asn_name', '')
                else:
                    ip = str(host)
                    if ip:
                        iocs["ips"].setdefault(
                            ip,
                            {"domains": [], "asn": "", "asn_name": "", "urls": [], "network_flows": []}
                        )
            
            domain_by_ip = {}
            for domain_name, domain_data in iocs["domains"].items():
                for ip in domain_data.get("ips", []):
                    domain_by_ip.setdefault(ip, []).append(domain_name)
            
            # URLs
            for request in network.get('http', []):
                if isinstance(request, dict):
                    url = request.get('uri', '')
                    if url:
                        host = request.get('host', '')
                        data = {
                            "host": host,
                            "method": request.get('method', ''),
                            "user-agent": request.get('user-agent', '')
                        }
                        iocs["urls"][url] = data

                        if host:
                            domain_entry = iocs["domains"].setdefault(host, {"ips": [], "urls": []})
                            if url not in domain_entry["urls"]:
                                domain_entry["urls"].append(url)

                            for ip in domain_entry["ips"]:
                                ip_entry = iocs["ips"].setdefault(
                                    ip,
                                    {"domains": [], "asn": "", "asn_name": "", "urls": [], "network_flows": []}
                                )
                                if url not in ip_entry["urls"]:
                                    ip_entry["urls"].append(url)
                                
                                    
            
            # Network flows
            for flow in network.get('tcp', []):
                if isinstance(flow, dict):
                    iocs["network_flows"].append(flow)
                    dst_ip = flow.get("dst", "")
                    if dst_ip:
                        ip_entry = iocs["ips"].setdefault(
                            dst_ip,
                            {"domains": [], "asn": "", "asn_name": "", "urls": [], "network_flows": []}
                        )
                        ip_entry["network_flows"].append(flow)
                        for domain_name in domain_by_ip.get(dst_ip, []):
                            domain_entry = iocs["domains"].setdefault(
                                domain_name,
                                {"ips": [], "urls": []}
                            )
                            if dst_ip not in domain_entry["ips"]:
                                domain_entry["ips"].append(dst_ip)
        
        # Extract from behavior section
        behavior = report_data.get('behavior', {})
        if isinstance(behavior, dict):
            # Processes
            for process in behavior.get('processes', [])[:BEHAVIOR_IOC_LIMIT]:
                if isinstance(process, dict):
                    process_name = process.get('process_name', '')
                    if not process_name:
                        continue

                    process_entry = iocs["processes"].setdefault(
                        process_name,
                        {"pid": process.get("process_id", ""), "files": [], "registry_keys": []}
                    )
                    
                    # API calls for file operations
                    for call in process.get('calls', [])[:BEHAVIOR_IOC_LIMIT]:
                        if isinstance(call, dict):
                            api = call.get('api', '')
                            if 'File' in api or 'Registry' in api:
                                for arg in call.get('arguments', [])[:BEHAVIOR_IOC_LIMIT]:
                                    if isinstance(arg, dict):
                                        name = arg.get('name', '')
                                        value = arg.get('value', '')
                                        if 'path' in name.lower() or 'file' in name.lower():
                                            file_entry = iocs["files"].setdefault(
                                                value,
                                                {"operations": [], "processes": []}
                                            )
                                            if api not in file_entry["operations"]:
                                                file_entry["operations"].append(api)
                                            if process_name not in file_entry["processes"]:
                                                file_entry["processes"].append(process_name)
                                            if value and value not in process_entry["files"]:
                                                process_entry["files"].append(value)
                                        elif 'key' in name.lower() or 'registry' in name.lower():
                                            registry_entry = iocs["registries"].setdefault(
                                                value,
                                                {"operations": [], "processes": []}
                                            )
                                            if api not in registry_entry["operations"]:
                                                registry_entry["operations"].append(api)
                                            if process_name not in registry_entry["processes"]:
                                                registry_entry["processes"].append(process_name)
                                            if value and value not in process_entry["registry_keys"]:
                                                process_entry["registry_keys"].append(value)
            
            # Mutexes
            for mutex in behavior.get('summary', {}).get('mutexes', [])[:BEHAVIOR_IOC_LIMIT]:
                mutex_name = str(mutex)
                if mutex_name:
                    iocs["mutexes"][mutex_name] = {"value": mutex_name}

        # Extract dropped files
        dropped = report_data.get('dropped', [])
        for drop in dropped:
            if isinstance(drop, dict) and drop:
                dropped_name = drop.get('name')[0] # que le premier nom du fichier droppé, pas besoin de tous les noms possibles pour un même fichier ...
                if not dropped_name:
                    continue
                
                iocs["dropped_files"][dropped_name] = {
                    'path': drop.get('guest_paths', []),
                    'size': drop.get('size', 0),
                    'md5': drop.get('md5', ''),
                    'sha256': drop.get('sha256', ''),
                    'yara': drop.get('yara', [])
                }
                
        
        return remove_empty_values(iocs)
        
    def extract_ttps(self, report_data: Dict[str, Any]): 
        """Extract TTP and MBC mappings from the CAPE report.

        This method parses the ``ttps`` section of the CAPE report and
        normalizes the output into a list of signature-centric entries. Each
        entry contains the signature name along with the associated ATT&CK-style
        TTP identifiers and Malware Behavior Catalog identifiers.

        Duplicate TTP and MBC identifiers are removed through set-based
        deduplication before the final result is produced.

        Args:
            report_data: Raw CAPE report content.

        Returns:
            A list of dictionaries, each describing a CAPE signature and the
            associated TTP and MBC identifiers.
        """    
        ttps = []

        # On récupère la liste des TTPs du rapport
        raw_ttps = report_data.get('ttps', [])
        
        for ttp_data in raw_ttps:
            if not isinstance(ttp_data, dict):
                continue
                
            # Utilisation de sets pour dédoublonner automatiquement
            # On utilise .get([], ...) pour s'assurer d'avoir une liste itérable
            unique_ttps = set(ttp_data.get('ttps', []))
            unique_mbcs = set(ttp_data.get('mbcs', []))
            
            ttp_entry = {
                "SignatureName": ttp_data.get('signature', 'Unknown'),
                # On reconvertit en liste pour le format JSON final
                "ID TTPs": list(unique_ttps),
                "ID MBCs": list(unique_mbcs)
            }
            
            ttps.append(ttp_entry)
            
        
        return ttps               
        
    def extract_signatures(self, report_data: Dict[str, Any]):
        """Extract behavioral signatures reported by CAPE.

        The CAPE ``signatures`` section is converted into a simplified list of
        dictionaries containing only the fields relevant for downstream
        processing: signature name, description and normalized severity label.

        Args:
            report_data: Raw CAPE report content.

        Returns:
            A list of extracted signatures with their associated description and
            mapped severity level.
        """      
        sig = []
        severity_map = {
            0: 'Informational',
            1: 'Low',
            2: 'Medium',
            3: 'High'
        }
        
        # Extract from main signatures
        for sig_data in report_data.get('signatures', []):
            if isinstance(sig_data, dict):
                sig_entry = {
                'name': sig_data.get('name', 'Unknown'),
                'description': sig_data.get('description', 'Unknown'),
                'severity': severity_map.get(sig_data.get('severity'), 'Unknown')
                }
                
                sig.append(sig_entry)
                
        
        return sig
    
    def extract_payloads_and_configs(self, report_data: Dict[str, Any]):
        """Extract payload metadata and configuration blocks from CAPE results.

        The method aggregates payload-related information from both the CAPE
        payload extraction section and dropped files that include configuration
        data. For each payload, selected hashes, file metadata, YARA matches and
        configuration content are preserved.

        Args:
            report_data: Raw CAPE report content.

        Returns:
            A list of payload dictionaries enriched with configuration and YARA
            information. Empty values are removed before the final list is
            returned.
        """
        
        payloads = []
    
        # Extract from CAPE section
        cape_data = report_data.get('CAPE', {}).get('payloads', []) 
        for payload_data in cape_data:
            if isinstance(payload_data, dict):
                payload ={
                    'Name': payload_data.get('name', 'Unknown'),
                    'Path': payload_data.get('path', ''),
                    'Size': payload_data.get('size', 0),
                    'Md5': payload_data.get('md5', ''),
                    'Sha256': payload_data.get('sha256', ''),
                    'Yara_Matches': [],
                    'Config': payload_data.get('config', {}),
                    'Payload_Type': payload_data.get('type', '')
                }
                
                for yara in payload_data.get('yara', []):
                    if isinstance(yara, dict):
                        payload['Yara_Matches'].append(yara.get('name', 'Unknown'))
                
                payloads.append(payload)
        
        # Extract from dropped files with configs
        dropped = report_data.get('dropped', [])
        for drop in dropped:
            if isinstance(drop, dict) and drop.get('config'):
                payload = {
                    'Name': drop.get('name', 'Dropped'),
                    'Path': drop.get('path', ''),
                    'Size': drop.get('size', 0),
                    'Md5': drop.get('md5', ''),
                    'Sha256': drop.get('sha256', ''),
                    'Yara_Matches': [],
                    'Config': drop.get('config', {}),
                    'Payload_Type': 'dropped'
                }
                
                for yara in payload_data.get('yara', []):
                    if isinstance(yara, dict):
                        payload['Yara_Matches'].append(yara.get('name', 'Unknown'))
                        
                payloads.append(payload)
        
        return remove_empty_values(payloads)
    
    def extract_processtree(self, report_data: Dict[str, Any]) :
        """Extract and normalize the process tree from CAPE behavior data.

        The returned structure contains two complementary views of the process
        execution data:
        - ``tree``: a hierarchical representation preserving parent/child
          relationships and depth;
        - ``details``: a flattened list of selected process metadata useful for
          quick inspection and downstream enrichment.

        Args:
            report_data: Raw CAPE report content.

        Returns:
            A dictionary containing the hierarchical process tree and a flat
            detail list. Empty values are removed recursively before returning.
        """
        
        raw_tree = report_data.get('behavior', {}).get('processtree', [])
        if not raw_tree and isinstance(report_data, list):
            raw_tree = report_data

        result = {
            'tree': [],
            'details': []
        }

        def walk(node: Dict[str, Any], depth: int = 0) -> Optional[Dict[str, Any]]:
            """Recursively walk a process tree node and normalize its content.

            The helper builds two synchronized views of the process tree:
            a flattened detail entry appended to ``result["details"]`` and a
            lightweight hierarchical node used in ``result["tree"]``.

            Args:
                node: Current process tree node extracted from CAPE.
                depth: Current depth level in the process tree.

            Returns:
                A normalized tree node with its children if the input node is a
                dictionary, otherwise ``None``.
            """
            if not isinstance(node, dict):
                return None

            environ = node.get('environ', {})
            
            # 1. Détails à plat (uniquement l'essentiel)
            process_flat = {
                'name': node.get('name', 'Unknown'),
                'path': node.get('module_path', 'Unknown'),
                'username': environ.get('UserName', 'Unknown'),
                'cmdline': environ.get('CommandLine', node.get('command_line', 'Unknown')),
            }
            result['details'].append(process_flat)

            # 2. Structure de l'arbre
            process_node = {
                'name': node.get('name', 'Unknown'),
                'depth': depth,
                'children': []
            }

            for child in node.get('children', []):
                child_item = walk(child, depth + 1)
                if child_item:
                    process_node['children'].append(child_item)

            return process_node

        for root_node in raw_tree:
            tree_node = walk(root_node, 0)
            if tree_node:
                result['tree'].append(tree_node)

        return remove_empty_values(result)
    
    def generate_consolidated_cape_report(self, task_id: int, report_data: Dict[str, Any], 
                                        sample_name: str, iocs, 
                                        signatures: List, score: int) -> str:
        """Build a consolidated JSON summary for the analyzed sample.

        The generated report is intended to be attached to a Karton task as a
        compact analysis artifact. It combines selected metadata from the CAPE
        report with a simplified threat assessment and an execution summary.

        Args:
            task_id: CAPE task identifier associated with the analysis.
            report_data: Raw CAPE report used as the source of metadata.
            sample_name: Original filename of the analyzed sample.
            iocs: IOC structure previously extracted from the CAPE report.
            signatures: Behavioral signatures extracted from the report.
            score: CAPE maliciousness score used to derive the threat level.

        Returns:
            A JSON-formatted string containing the consolidated CAPE analysis
            report.
        """        
        info = report_data.get("info", {})
        target = report_data.get("target", {})
        info_machine = info.get('machine', {})  

        # Build professional consolidated report
        report = {
            "analysis_metadata": {
                "task_id": task_id,
                "analyzer": "CAPE Sandbox",
                "cape_url": f"{self.api_url}/analysis/{task_id}/",
                "name_machine": info_machine.get('name', 'Unknown'),
                "manager_machine": info_machine.get('manager', 'Unknown'),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "status": "success",
                "duration": info.get("duration", 0)
            },
            "sample_information": {
                "filename": sample_name,
                "size": target.get("file", {}).get("size", 0),
                "md5": target.get("file", {}).get("md5", ""),
                "sha1": target.get("file", {}).get("sha1", ""),
                "sha256": target.get("file", {}).get("sha256", ""),
                "filetype": target.get("file", {}).get("type", "")
            },
            "threat_assessment": {
                "score": score,
                "risk_level": "high" if score >= 8 else "medium" if score >= 5 else "low" if score >= 2 else "clean",
            },
            "summary": {
                "analysis_verdict": f"Score {score}/10 - {len(signatures)} behavioral signatures detected",
                "key_findings": [
                    f"Contacted {len(iocs.get('domains', {}))} domains and {len(iocs.get('ips', {}))} IP addresses",
                    f"Dropped {len(iocs.get('dropped_files', {}))} files during execution",
                    f"Triggered {len(signatures)} detection signatures",
                    f"Analysis duration: {info.get('duration', 0)} seconds"
                ],
                "recommendation": "high" if score >= 7 else "medium" if score >= 4 else "low"
            },
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def create_error_report(self, sample_resource: Resource, sample_name: str, error_message: str):
        """Create and send an error report task to Karton.

        When a CAPE submission, execution, or report retrieval step fails, this
        helper creates a synthetic analysis report describing the failure and
        sends it downstream as a Karton task so that the pipeline still receives
        a terminal result for the sample.

        Args:
            sample_resource: Original Karton resource corresponding to the
                analyzed sample.
            sample_name: Original sample filename.
            error_message: Human-readable message describing the failure.
        """
        
        error_report = {
            "analysis_metadata": {
                "analyzer": "CAPE Sandbox",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "status": "error"
            },
            "sample_information": {
                "filename": sample_name
            },
            "error": {
                "message": error_message,
                "reason": "CAPE analysis could not be completed"
            },
            "summary": {
                "analysis_verdict": "Analysis failed - no threat assessment available",
                "recommendation": "Manual analysis required"
            }
        }
        
        error_json = json.dumps(error_report, indent=2)
        error_resource = Resource(f"{sample_name}_cape_error", error_json.encode('utf-8'))
        
        try:
            task = Task(
                {"type": "sample", "stage": "analyzed"},
                payload={
                    "parent": sample_resource,
                    "sample": error_resource
                }
            )
            task.add_payload("tags", ["karton:cape", "error"])
            self.send_task(task)
            self.log.info(f"Sent CAPE error report for {sample_name}")
        except Exception as e:
            self.log.error(f"Failed to send CAPE error report: {str(e)}")
    
    def set_attributes(self, iocs, signatures, ttps, payloads, processtree) -> Dict[str, Any]:
        """Assemble the Karton analysis attributes extracted from CAPE.

        This method builds the ``attributes`` payload attached to the final
        Karton task. Only non-empty sections are included. When a section is
        present, a corresponding CAPE tag is also added to ``self.tags``.

        Args:
            iocs: IOC structure extracted from the CAPE report.
            signatures: Behavioral signatures extracted from the report.
            ttps: TTP and MBC mapping entries extracted from the report.
            payloads: Extracted payloads and configuration objects.
            processtree: Normalized process tree data.

        Returns:
            A dictionary containing the non-empty analysis attributes that must
            be attached to the outgoing Karton task.
        """
        
        attributes = {}

        # 3. On ajoute seulement si la liste n'est pas vide
        if iocs:
            attributes['iocs'] = iocs
            self.set_tags("karton:capeV2:iocs")
        
        if signatures:
            attributes['signatures'] = signatures
            self.set_tags("karton:capeV2:signatures")
            
            
        if ttps:
            attributes['ttps'] = ttps
            self.set_tags("karton:capeV2:ttps")
            
        if payloads:
            attributes['payloads'] = payloads
            self.set_tags("karton:capeV2:payloads")
            
        if processtree:
            attributes['processtree'] = processtree
            self.set_tags("karton:capeV2:processtree")

        return attributes
    
    def set_tags(self, value, score: int=None) -> List[str]:
        """Append CAPE-related tags to the current analysis context.

        The method adds a custom tag to ``self.tags`` and, when a maliciousness
        score is provided, also derives a threat-level tag from that score.

        Args:
            value: Tag value to append to the current tag list.
            score: Optional CAPE maliciousness score used to derive an
                additional threat-level tag.

        Returns:
            The method does not explicitly return a value. Tags are appended
            directly to ``self.tags``.
        """
        self.tags.append(value)

        
        # Add threat score indicator
        if isinstance(score, int):     
            if score >= 8:
                self.append("karton:capeV2:threat:high")
            elif score >= 5:
                self.append("karton:capeV2:threat:medium")
            elif score >= 2:
                self.append("karton:capeV2:threat:low")
            else:
                self.append("karton:capeV2:threat:clean")
    
    #TODO : VT TI Comment dans les comment du reporter mwdb (VT Community --> Comment mwdb)
    #TODO : call api --> parsgin json community
    
    def process(self, task: Task) -> None:
        """Process a Karton sample task through the CAPE analysis pipeline.

        This is the main entry point executed by Karton for each incoming task.
        The method performs the complete analysis workflow:

        1. Retrieve the sample resource from the task.
        2. Decide whether the sample should be analyzed by CAPE.
        3. Submit the sample to CAPE.
        4. Wait for analysis completion.
        5. Retrieve the final CAPE report.
        6. Extract intelligence artifacts from the report.
        7. Build a consolidated report and forward a new analyzed task.

        If any stage fails, an error report is generated and sent instead of the
        standard analysis output.

        Args:
            task: Karton task containing the sample resource to analyze.
        """
        
        try:
            sample_resource = task.get_resource("sample")
        except TypeError:
            self.log.error("No sample resource found in task, skipping")
            return
            
        sample_name = sample_resource.name or "unknown_sample"
        self.log.info(f"Hi {sample_name}, let me analyze you with CAPE!")
    
        
        # Check if file should be processed
        if not self.should_process_file(sample_name, len(sample_resource.content)):
            self.log.info(f"Skipping {sample_name} - not suitable for CAPE analysis")
            return
        
        try:
            # Download the resource to a temporary file
            with sample_resource.download_temporary_file() as sample_file:
                file_path = sample_file.name
                
                # Submit sample to CAPE
                task_id = self.submit_sample(file_path, sample_name)
                self.set_tags(f"cape:id:{task_id}")
                
                if not task_id:
                    self.log.error(f"Failed to submit sample {sample_name} to CAPE")
                    # Create error report
                    self.create_error_report(sample_resource, sample_name, "Failed to submit to CAPE")
                    return
                
                # Wait for analysis to complete
                if not self.wait_for_analysis(task_id):
                    self.log.error(f"Analysis did not complete for sample {sample_name} (Task ID: {task_id})")
                    self.create_error_report(sample_resource, sample_name, "Analysis timeout")
                    return
                
                # Retrieve comprehensive analysis results
                results = self.get_comprehensive_analysis_results(task_id)
                
                if not results:
                    self.log.error(f"Failed to retrieve comprehensive results for {sample_name} (Task ID: {task_id})")
                    self.create_error_report(sample_resource, sample_name, "Failed to retrieve results")
                    return
                
                #TODO ---------------------APPELL FONCTION ---------------------------------
                # Extract IOCs for tagging
                iocs = self.extract_iocs(results)
                signatures = self.extract_signatures(results)
                ttps = self.extract_ttps(results)
                processtree = self.extract_processtree(results)
                payloads = self.extract_payloads_and_configs(results)
                
                
                
                
                score = results.get("malscore", 0)
                sha256sum_file = results.get("target", {}).get("file", {}).get("sha256", "")

                
                # Create single consolidated resource
                consolidated_report = self.generate_consolidated_cape_report(task_id, results, sample_name, iocs, signatures, score)
                
                
                report_name = f"{sample_name}_capeV2_analysis"
                report_resource = Resource(report_name, consolidated_report.encode('utf-8'))
                
                
                
                attributes =  self.set_attributes(iocs, signatures, ttps, payloads, processtree)

                #TODO ------------------------------------------------------

                analysis_task = Task(
                    {"type": "sample", "stage": "analyzed"},
                    payload={
                        "parent": sample_resource, 
                        "sample": report_resource,
                        "attributes" : attributes,
                        "comments": [
                            f"CAPEv2 analysis: {self.api_url}/analysis/{task_id}/",
                            f"VT analysis: https://www.virustotal.com/gui/file/{sha256sum_file}/",
                            #TODO : comments VT de la community en string
                        ]
                    }
                )
                
                
                analysis_task.add_payload("tags", self.tags) #tags dans cette attributs python : self.tags
                self.send_task(analysis_task)
                
        except Exception as e:
            self.log.error(f"Error processing sample {sample_name} with CAPE: {str(e)}")
            self.create_error_report(sample_resource, sample_name, f"Processing error: {str(e)}")
            return

if __name__ == "__main__":
    CapeKarton().loop()
