#!/usr/bin/env python3
"""Docker Compose 配置分析 CLI 工具"""

import argparse
import copy
import os
import re
import socket
import sys
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


# =============================================================================
# 1. Compose 解析模块
# =============================================================================

class ComposeParser:
    """Compose 文件解析器，支持多文件合并"""

    def __init__(self):
        self.merged_config: Dict[str, Any] = {}

    @staticmethod
    def _load_yaml(file_path: str) -> Dict[str, Any]:
        """加载单个 YAML 文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """深度合并两个字典，override 优先"""
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ComposeParser._deep_merge(result[key], value)
            elif key in result and isinstance(result[key], list) and isinstance(value, list):
                result[key] = ComposeParser._merge_lists(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result

    @staticmethod
    def _merge_lists(base: List[Any], override: List[Any]) -> List[Any]:
        """合并列表，对于带冒号的映射（如 ports、volumes）按目标去重"""
        def get_key(item: Any) -> str:
            if isinstance(item, str):
                parts = item.split(':')
                return parts[-1] if len(parts) >= 2 else item
            elif isinstance(item, dict):
                # 对于字典形式的配置，尝试找到 target 字段
                return item.get('target', str(item))
            return str(item)

        merged = {}
        for item in base:
            merged[get_key(item)] = item
        for item in override:
            merged[get_key(item)] = item
        return list(merged.values())

    def parse(self, file_paths: List[str]) -> Dict[str, Any]:
        """解析并合并多个 Compose 文件"""
        if not file_paths:
            raise ValueError("至少需要提供一个 Compose 文件路径")

        merged: Dict[str, Any] = {}
        for path in file_paths:
            config = self._load_yaml(path)
            if not merged:
                merged = config
            else:
                merged = self._deep_merge(merged, config)

        self.merged_config = merged
        return merged

    def get_services(self) -> Dict[str, Dict[str, Any]]:
        """获取所有服务配置"""
        return self.merged_config.get('services', {}) or {}

    def get_networks(self) -> Dict[str, Dict[str, Any]]:
        """获取所有网络配置"""
        return self.merged_config.get('networks', {}) or {}

    def get_volumes(self) -> Dict[str, Dict[str, Any]]:
        """获取所有卷配置"""
        return self.merged_config.get('volumes', {}) or {}


# =============================================================================
# 2. 依赖图分析模块
# =============================================================================

class DependencyAnalyzer:
    """依赖关系分析器"""

    def __init__(self, services: Dict[str, Dict[str, Any]]):
        self.services = services
        self.dependencies: Dict[str, Set[str]] = defaultdict(set)
        self.dependents: Dict[str, Set[str]] = defaultdict(set)
        self.network_groups: Dict[str, Set[str]] = defaultdict(set)
        self.service_networks: Dict[str, Set[str]] = defaultdict(set)
        self._build_graph()

    def _add_dependency(self, service: str, dependency: str):
        """添加依赖关系"""
        if dependency in self.services and dependency != service:
            self.dependencies[service].add(dependency)
            self.dependents[dependency].add(service)

    @staticmethod
    def _extract_network_names(networks_config: Any) -> List[str]:
        """从 networks 配置中提取网络名称列表"""
        if isinstance(networks_config, dict):
            return list(networks_config.keys())
        elif isinstance(networks_config, list):
            names = []
            for n in networks_config:
                if isinstance(n, str):
                    names.append(n)
                elif isinstance(n, dict):
                    names.extend(n.keys())
            return names
        elif isinstance(networks_config, str):
            return [networks_config]
        return ['default']

    def _has_path(self, src: str, dst: str) -> bool:
        """检查是否存在从 src 到 dst 的路径（BFS）"""
        if src == dst:
            return True
        visited = set()
        queue = deque([src])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for neighbor in self.dependencies.get(node, set()):
                if neighbor == dst:
                    return True
                if neighbor not in visited:
                    queue.append(neighbor)
        return False

    def _build_graph(self):
        """构建依赖图"""
        # 第一阶段：收集每个服务的网络归属
        for name, config in self.services.items():
            networks_config = config.get('networks')
            network_names = self._extract_network_names(networks_config)
            if not network_names:
                network_names = ['default']
            for net in network_names:
                self.network_groups[net].add(name)
                self.service_networks[name].add(net)

        # 第二阶段：从 depends_on 提取强依赖
        for name, config in self.services.items():
            depends_on = config.get('depends_on', [])
            if isinstance(depends_on, dict):
                for dep in depends_on.keys():
                    self._add_dependency(name, dep)
            elif isinstance(depends_on, list):
                for dep in depends_on:
                    if isinstance(dep, str):
                        self._add_dependency(name, dep)
                    elif isinstance(dep, dict):
                        for dep_name in dep.keys():
                            self._add_dependency(name, dep_name)

        # 第三阶段：从环境变量中推断服务名引用（强依赖）
        for name, config in self.services.items():
            env = config.get('environment', {})
            env_values = []
            if isinstance(env, dict):
                env_values = list(env.values())
            elif isinstance(env, list):
                for item in env:
                    if isinstance(item, str) and '=' in item:
                        env_values.append(item.split('=', 1)[1])

            service_names = set(self.services.keys())
            for val in env_values:
                if not isinstance(val, str):
                    continue
                # 去掉变量引用展开的花括号内容，避免 ${VAR:-default} 中的 default 可能偶然匹配服务名
                # 只保留实际字面量部分（去掉 $ 开头引用的内容）
                cleaned_val = re.sub(r'\$\{[^}]+\}', '', val)
                # 检查是否明确引用了其他服务名（主机名格式，如 "service_name:port 或 http://service_name/ 等）
                # 更严格：只有服务名作为独立标识符，不是其他单词的子串
                for svc in service_names:
                    if svc == name:
                        continue
                    # 使用单词边界匹配，避免 wordpress 匹配 wordpress 匹配默认值
                    pattern = re.compile(r'(?<![a-zA-Z0-9_])' + re.escape(svc) + r'(?![a-zA-Z0-9_])')
                    if pattern.search(cleaned_val):
                        self._add_dependency(name, svc)
                        break

        # 第四阶段：从共享网络推断弱依赖（拓扑参考）
        # 仅对完全没有任何强依赖关系（既不依赖也不被依赖）的孤立服务，按网络分组建立引用
        # 严格避免产生循环依赖：添加前检查是否存在反向路径
        for net, members in self.network_groups.items():
            if len(members) < 2:
                continue
            sorted_members = sorted(members)
            for i, svc in enumerate(sorted_members):
                # 跳过已有强依赖或者被其他服务依赖的服务，避免引入循环
                if self.dependencies.get(svc) or self.dependents.get(svc):
                    continue
                # 找到同组中第一个满足：other 也没有依赖/被依赖，且 other 到 svc 没有路径
                for other in sorted_members[i + 1:]:
                    if self.dependencies.get(other) or self.dependents.get(other):
                        continue
                    # 确保不会形成循环：other 不能有路径到达 svc
                    if not self._has_path(other, svc):
                        self._add_dependency(svc, other)
                        break

    def get_network_groups(self) -> Dict[str, Set[str]]:
        """获取按网络分组的服务"""
        return dict(self.network_groups)

    def detect_cycles(self) -> List[List[str]]:
        """检测循环依赖，使用 Tarjan 算法"""
        index_counter = [0]
        stack: List[str] = []
        lowlinks: Dict[str, int] = {}
        index: Dict[str, int] = {}
        on_stack: Dict[str, bool] = defaultdict(bool)
        result: List[List[str]] = []

        def strongconnect(node: str):
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack[node] = True

            for successor in self.dependencies.get(node, set()):
                if successor not in index:
                    strongconnect(successor)
                    lowlinks[node] = min(lowlinks[node], lowlinks[successor])
                elif on_stack[successor]:
                    lowlinks[node] = min(lowlinks[node], index[successor])

            if lowlinks[node] == index[node]:
                component: List[str] = []
                while True:
                    successor = stack.pop()
                    on_stack[successor] = False
                    component.append(successor)
                    if successor == node:
                        break
                if len(component) > 1:
                    result.append(component)

        for node in self.services:
            if node not in index:
                strongconnect(node)

        return result

    def topological_sort(self) -> List[str]:
        """拓扑排序，返回启动顺序"""
        in_degree: Dict[str, int] = {svc: 0 for svc in self.services}
        for svc in self.services:
            for dep in self.dependencies.get(svc, set()):
                in_degree[svc] += 1

        queue = deque([svc for svc, deg in in_degree.items() if deg == 0])
        result: List[str] = []

        while queue:
            node = queue.popleft()
            result.append(node)
            for dependent in self.dependents.get(node, set()):
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(result) != len(self.services):
            remaining = [s for s in self.services if s not in result]
            result.extend(sorted(remaining))

        return result

    def to_ascii_graph(self) -> str:
        """生成 ASCII 依赖图"""
        lines: List[str] = []
        lines.append("Docker Compose 服务依赖图")
        lines.append("=" * 60)

        # 网络分组信息
        if self.network_groups:
            lines.append("")
            lines.append("📡 按网络分组的服务:")
            for net in sorted(self.network_groups.keys()):
                members = sorted(self.network_groups[net])
                lines.append(f"  {net}: {', '.join(members)}")
            lines.append("")
            lines.append("-" * 60)

        lines.append("")
        lines.append("🔗 依赖关系:")
        topo = self.topological_sort()
        for svc in topo:
            deps = sorted(self.dependencies.get(svc, set()))
            if deps:
                for i, dep in enumerate(deps):
                    connector = "└── " if i == len(deps) - 1 else "├── "
                    if i == 0:
                        lines.append(f"{svc}")
                    else:
                        lines.append(f"{' ' * len(svc)}")
                    lines[-1] += f" {connector}{dep}"
            else:
                lines.append(f"{svc} (无依赖)")

        lines.append("")
        lines.append("启动顺序（拓扑排序）:")
        lines.append("  → ".join(topo))

        cycles = self.detect_cycles()
        if cycles:
            lines.append("")
            lines.append("⚠️  检测到循环依赖:")
            for cycle in cycles:
                lines.append(f"  {' → '.join(cycle)} → {cycle[0]}")

        return "\n".join(lines)

    def to_dot(self) -> str:
        """生成 Graphviz DOT 格式"""
        lines: List[str] = []
        lines.append("digraph compose_dependencies {")
        lines.append('    rankdir=LR;')
        lines.append('    node [shape=box, style=filled, fillcolor="#e3f2fd", fontname="Helvetica"];')
        lines.append('    edge [color="#1976d2"];')
        lines.append('    compound=true;')
        lines.append('')

        # 用 subgraph cluster 展示网络分组
        network_colors = [
            '#bbdefb', '#c8e6c9', '#fff9c4', '#ffccbc', '#f8bbd0',
            '#d1c4e9', '#b2ebf2', '#f0f4c3', '#ffe0b2', '#e1bee7'
        ]
        for i, (net, members) in enumerate(sorted(self.network_groups.items())):
            if len(members) < 2:
                continue
            color = network_colors[i % len(network_colors)]
            cluster_name = re.sub(r'[^a-zA-Z0-9_]', '_', f'cluster_{net}')
            lines.append(f'    subgraph {cluster_name} {{')
            lines.append(f'        label = "网络: {net}";')
            lines.append(f'        style = filled;')
            lines.append(f'        color = "{color}";')
            lines.append(f'        fillcolor = "{color}40";')
            for svc in sorted(members):
                lines.append(f'        "{svc}";')
            lines.append('    }')
            lines.append('')

        # 节点定义（未在任何网络cluster中的服务）
        for svc in sorted(self.services.keys()):
            in_cluster = False
            for members in self.network_groups.values():
                if svc in members and len(members) >= 2:
                    in_cluster = True
                    break
            if not in_cluster:
                deps = sorted(self.dependencies.get(svc, set()))
                label_parts = [svc]
                config = self.services[svc]
                if 'image' in config:
                    label_parts.append(f"image: {config['image']}")
                elif 'build' in config:
                    label_parts.append(f"build: {config['build'] if isinstance(config['build'], str) else './...'}")
                label = '\\n'.join(label_parts)
                lines.append(f'    "{svc}" [label="{label}"];')

        # 更新cluster中节点的标签（带image/build信息）
        for svc in sorted(self.services.keys()):
            label_parts = [svc]
            config = self.services[svc]
            if 'image' in config:
                label_parts.append(f"image: {config['image']}")
            elif 'build' in config:
                label_parts.append(f"build: {config['build'] if isinstance(config['build'], str) else './...'}")
            label = '\\n'.join(label_parts)
            lines.append(f'    "{svc}" [label="{label}"];')

        lines.append('')

        cycles = self.detect_cycles()
        cycle_nodes = set()
        for cycle in cycles:
            cycle_nodes.update(cycle)

        for svc in sorted(self.services.keys()):
            for dep in sorted(self.dependencies.get(svc, set())):
                color = '#f44336' if svc in cycle_nodes and dep in cycle_nodes else '#1976d2'
                style = 'dashed' if svc in cycle_nodes and dep in cycle_nodes else 'solid'
                lines.append(f'    "{svc}" -> "{dep}" [color="{color}", style={style}];')

        lines.append('}')
        return "\n".join(lines)


# =============================================================================
# 3. 端口检查模块
# =============================================================================

class PortChecker:
    """端口冲突检查器"""

    @staticmethod
    def parse_port_mapping(port_str: Any) -> List[Dict[str, Any]]:
        """解析端口映射，支持多种格式"""
        results: List[Dict[str, Any]] = []

        if isinstance(port_str, dict):
            published = port_str.get('published')
            target = port_str.get('target')
            protocol = port_str.get('protocol', 'tcp')
            host_ip = port_str.get('host_ip', '0.0.0.0')
            if published is not None and target is not None:
                results.append({
                    'published': int(published),
                    'target': int(target),
                    'protocol': protocol,
                    'host_ip': host_ip,
                    'range': False
                })
            return results

        if not isinstance(port_str, str):
            return results

        parts = port_str.split('/')
        protocol = parts[1] if len(parts) > 1 else 'tcp'
        main_part = parts[0]

        segments = main_part.split(':')

        if len(segments) == 1:
            port_spec = segments[0]
            if '-' in port_spec:
                start, end = map(int, port_spec.split('-'))
                for p in range(start, end + 1):
                    results.append({
                        'published': p,
                        'target': p,
                        'protocol': protocol,
                        'host_ip': '0.0.0.0',
                        'range': True
                    })
            else:
                port = int(port_spec)
                results.append({
                    'published': port,
                    'target': port,
                    'protocol': protocol,
                    'host_ip': '0.0.0.0',
                    'range': False
                })

        elif len(segments) == 2:
            host_spec, container_spec = segments
            results.extend(PortChecker._parse_two_parts(host_spec, container_spec, protocol, '0.0.0.0'))

        elif len(segments) >= 3:
            host_ip = segments[0]
            host_spec = segments[1]
            container_spec = ':'.join(segments[2:])
            results.extend(PortChecker._parse_two_parts(host_spec, container_spec, protocol, host_ip))

        return results

    @staticmethod
    def _parse_two_parts(host_spec: str, container_spec: str, protocol: str, host_ip: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        is_range = '-' in host_spec

        if '-' in host_spec and '-' in container_spec:
            h_start, h_end = map(int, host_spec.split('-'))
            c_start, c_end = map(int, container_spec.split('-'))
            h_len = h_end - h_start + 1
            c_len = c_end - c_start + 1
            length = min(h_len, c_len)
            for i in range(length):
                results.append({
                    'published': h_start + i,
                    'target': c_start + i,
                    'protocol': protocol,
                    'host_ip': host_ip,
                    'range': True
                })
        elif '-' in host_spec:
            h_start, h_end = map(int, host_spec.split('-'))
            target = int(container_spec)
            for p in range(h_start, h_end + 1):
                results.append({
                    'published': p,
                    'target': target,
                    'protocol': protocol,
                    'host_ip': host_ip,
                    'range': True
                })
        else:
            published = int(host_spec)
            if '-' in container_spec:
                c_start, c_end = map(int, container_spec.split('-'))
                for p in range(c_start, c_end + 1):
                    results.append({
                        'published': published,
                        'target': p,
                        'protocol': protocol,
                        'host_ip': host_ip,
                        'range': True
                    })
            else:
                target = int(container_spec)
                results.append({
                    'published': published,
                    'target': target,
                    'protocol': protocol,
                    'host_ip': host_ip,
                    'range': is_range
                })

        return results

    @staticmethod
    def check_port_available(port: int, host_ip: str = '0.0.0.0', protocol: str = 'tcp') -> bool:
        """检查端口在系统中是否可用"""
        sock_type = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, sock_type)
            if host_ip == '0.0.0.0':
                sock.bind(('', port))
            else:
                sock.bind((host_ip, port))
            return True
        except OSError:
            return False
        finally:
            if sock:
                sock.close()

    def analyze(self, services: Dict[str, Dict[str, Any]], check_system: bool = True) -> Dict[str, Any]:
        """分析端口配置"""
        all_ports: List[Dict[str, Any]] = []
        service_ports: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for name, config in services.items():
            ports_config = config.get('ports', []) or []
            for port_cfg in ports_config:
                parsed_list = self.parse_port_mapping(port_cfg)
                for parsed in parsed_list:
                    entry = {
                        'service': name,
                        **parsed
                    }
                    all_ports.append(entry)
                    service_ports[name].append(entry)

        conflicts: List[Dict[str, Any]] = []
        container_conflicts: List[Dict[str, Any]] = []
        system_conflicts: List[Dict[str, Any]] = []
        range_overlaps: List[Dict[str, Any]] = []

        # 检查宿主机端口冲突
        for i in range(len(all_ports)):
            for j in range(i + 1, len(all_ports)):
                p1, p2 = all_ports[i], all_ports[j]
                if (p1['host_ip'] == p2['host_ip'] or p1['host_ip'] == '0.0.0.0' or p2['host_ip'] == '0.0.0.0'):
                    if p1['published'] == p2['published'] and p1['protocol'] == p2['protocol']:
                        conflicts.append({
                            'type': 'host_port_conflict',
                            'port': p1['published'],
                            'protocol': p1['protocol'],
                            'services': [p1['service'], p2['service']],
                            'details': f"宿主机端口 {p1['published']}/{p1['protocol']} 被 {p1['service']} 和 {p2['service']} 同时占用"
                        })

        # 检查容器端口重复（同服务内）
        for svc, ports in service_ports.items():
            target_ports: Dict[Tuple[int, str], List[Dict[str, Any]]] = defaultdict(list)
            for p in ports:
                target_ports[(p['target'], p['protocol'])].append(p)
            for (target, proto), port_list in target_ports.items():
                if len(port_list) > 1:
                    container_conflicts.append({
                        'type': 'container_port_duplicate',
                        'service': svc,
                        'port': target,
                        'protocol': proto,
                        'details': f"服务 {svc} 内容器端口 {target}/{proto} 映射了 {len(port_list)} 次"
                    })

        # 检查端口范围重叠
        range_ports = [p for p in all_ports if p['range']]
        if range_ports:
            by_service: Dict[str, List[int]] = defaultdict(list)
            for p in range_ports:
                by_service[p['service']].append(p['published'])
            for svc, published_list in by_service.items():
                published_list.sort()
                for k in range(len(published_list) - 1):
                    if published_list[k + 1] == published_list[k] + 1:
                        continue
                    if published_list[k + 1] <= published_list[k]:
                        range_overlaps.append({
                            'type': 'range_overlap',
                            'service': svc,
                            'details': f"服务 {svc} 的端口范围存在重叠"
                        })
                        break

        # 检查系统端口占用
        if check_system:
            checked = set()
            for p in all_ports:
                key = (p['host_ip'], p['published'], p['protocol'])
                if key in checked:
                    continue
                checked.add(key)
                if not self.check_port_available(p['published'], p['host_ip'], p['protocol']):
                    system_conflicts.append({
                        'type': 'system_port_in_use',
                        'service': p['service'],
                        'port': p['published'],
                        'protocol': p['protocol'],
                        'host_ip': p['host_ip'],
                        'details': f"服务 {p['service']} 映射的端口 {p['host_ip']}:{p['published']}/{p['protocol']} 当前系统已被占用"
                    })

        return {
            'all_ports': all_ports,
            'service_ports': dict(service_ports),
            'conflicts': conflicts,
            'container_conflicts': container_conflicts,
            'system_conflicts': system_conflicts,
            'range_overlaps': range_overlaps
        }

    def format_report(self, analysis: Dict[str, Any]) -> str:
        """格式化端口分析报告"""
        lines: List[str] = []
        lines.append("端口分析报告")
        lines.append("=" * 60)

        lines.append("\n📋 端口映射表:")
        lines.append(f"{'服务':<20} {'宿主机映射':<25} {'容器端口':<15} {'协议':<8}")
        lines.append("-" * 70)
        for svc in sorted(analysis['service_ports'].keys()):
            ports = analysis['service_ports'][svc]
            for i, p in enumerate(ports):
                svc_display = svc if i == 0 else ' ' * 20
                host_display = f"{p['host_ip']}:{p['published']}"
                lines.append(f"{svc_display:<20} {host_display:<25} {p['target']:<15} {p['protocol']:<8}")

        issues_found = False

        if analysis['conflicts']:
            issues_found = True
            lines.append("\n🚨 宿主机端口冲突:")
            for c in analysis['conflicts']:
                lines.append(f"  ❌ {c['details']}")

        if analysis['container_conflicts']:
            issues_found = True
            lines.append("\n⚠️  容器端口重复:")
            for c in analysis['container_conflicts']:
                lines.append(f"  ⚠️  {c['details']}")

        if analysis['range_overlaps']:
            issues_found = True
            lines.append("\n⚠️  端口范围重叠:")
            for c in analysis['range_overlaps']:
                lines.append(f"  ⚠️  {c['details']}")

        if analysis['system_conflicts']:
            issues_found = True
            lines.append("\n🚨 系统端口占用:")
            for c in analysis['system_conflicts']:
                lines.append(f"  ❌ {c['details']}")

        if not issues_found:
            lines.append("\n✅ 未发现端口冲突问题")

        return "\n".join(lines)


# =============================================================================
# 4. 配置风险检查模块
# =============================================================================

class RiskChecker:
    """配置风险检查器"""

    PASSWORD_KEYWORDS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
        'apikey', 'access_key', 'private_key', 'credentials',
        'database_url', 'db_password', 'mysql_password',
        'postgres_password', 'redis_password', 'mongodb_password'
    ]

    RISK_LEVELS = {
        'critical': '🔴 严重',
        'high': '🟠 高危',
        'medium': '🟡 中危',
        'low': '🔵 低危'
    }

    def __init__(self):
        self.risks: List[Dict[str, Any]] = []

    def _add_risk(self, level: str, category: str, service: str, message: str,
                  suggestion: str, fix_patch: Optional[Dict[str, Any]] = None):
        self.risks.append({
            'level': level,
            'category': category,
            'service': service,
            'message': message,
            'suggestion': suggestion,
            'fix_patch': fix_patch
        })

    def analyze(self, services: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """分析所有风险"""
        self.risks = []

        for name, config in services.items():
            self._check_plaintext_passwords(name, config)
            self._check_latest_tag(name, config)
            self._check_restart_policy(name, config)
            self._check_docker_socket(name, config)
            self._check_privileged(name, config)
            self._check_healthcheck(name, config)
            self._check_root_user(name, config)
            self._check_excessive_caps(name, config)

        return sorted(self.risks, key=lambda r: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[r['level']])

    def _check_plaintext_passwords(self, service: str, config: Dict[str, Any]):
        """检查明文密码环境变量"""
        env = config.get('environment', {})
        env_items: List[Tuple[str, Any]] = []

        if isinstance(env, dict):
            env_items = list(env.items())
        elif isinstance(env, list):
            for item in env:
                if isinstance(item, str) and '=' in item:
                    k, v = item.split('=', 1)
                    env_items.append((k, v))

        for key, value in env_items:
            key_lower = key.lower()
            if any(kw in key_lower for kw in self.PASSWORD_KEYWORDS):
                if value and isinstance(value, str) and not value.startswith('${'):
                    self._add_risk(
                        level='high',
                        category='security',
                        service=service,
                        message=f"环境变量 {key} 包含明文密码/密钥",
                        suggestion=f"使用 Docker Secrets 或 .env 文件引用（如 ${key}）代替硬编码",
                        fix_patch={
                            'type': 'environment',
                            'service': service,
                            'key': key,
                            'value': f'${{{key}}}'
                        }
                    )

    def _check_latest_tag(self, service: str, config: Dict[str, Any]):
        """检查 latest 镜像标签"""
        image = config.get('image', '')
        if isinstance(image, str) and image:
            if ':' not in image or image.endswith(':latest'):
                self._add_risk(
                    level='medium',
                    category='stability',
                    service=service,
                    message=f"镜像 {image} 使用了 latest 标签或未指定标签",
                    suggestion="指定明确的版本标签（如 image:v1.2.3）以保证可复现性",
                    fix_patch={
                        'type': 'image_tag',
                        'service': service,
                        'current_image': image,
                        'suggestion': '请替换为具体版本号'
                    }
                )

    def _check_restart_policy(self, service: str, config: Dict[str, Any]):
        """检查重启策略"""
        restart = config.get('restart')
        deploy = config.get('deploy', {}) or {}
        restart_policy = deploy.get('restart_policy', {}) or {}

        has_policy = restart is not None or restart_policy.get('condition') is not None

        if not has_policy:
            self._add_risk(
                level='medium',
                category='reliability',
                service=service,
                message="未设置重启策略",
                suggestion="添加 restart: unless-stopped 或 on-failure 策略",
                fix_patch={
                    'type': 'add_restart',
                    'service': service,
                    'restart': 'unless-stopped'
                }
            )

    def _check_docker_socket(self, service: str, config: Dict[str, Any]):
        """检查是否挂载了 Docker socket"""
        volumes = config.get('volumes', []) or []
        for vol in volumes:
            vol_str = vol if isinstance(vol, str) else (vol.get('source') or '')
            if 'docker.sock' in vol_str:
                self._add_risk(
                    level='critical',
                    category='security',
                    service=service,
                    message=f"挂载了 Docker socket: {vol_str}",
                    suggestion="移除 Docker socket 挂载，除非绝对必要。若必须使用，考虑使用 Docker Socket Proxy",
                    fix_patch=None
                )

    def _check_privileged(self, service: str, config: Dict[str, Any]):
        """检查特权模式"""
        if config.get('privileged') is True:
            self._add_risk(
                level='critical',
                category='security',
                service=service,
                message="容器运行在特权模式 (privileged: true)",
                suggestion="使用具体的 cap_add 替代 privileged，仅授予必要的 capabilities",
                fix_patch={
                    'type': 'remove_privileged',
                    'service': service
                }
            )

    def _check_healthcheck(self, service: str, config: Dict[str, Any]):
        """检查是否缺失健康检查"""
        healthcheck = config.get('healthcheck')
        image = config.get('image', '') or ''

        skip_images = ['busybox', 'alpine', 'scratch']
        skip_flag = any(s in image.lower() for s in skip_images)

        if not healthcheck and not skip_flag:
            self._add_risk(
                level='low',
                category='observability',
                service=service,
                message="未配置 healthcheck 健康检查",
                suggestion="添加健康检查配置，示例：test: [\"CMD\", \"curl\", \"-f\", \"http://localhost/\"]",
                fix_patch={
                    'type': 'add_healthcheck',
                    'service': service,
                    'healthcheck': {
                        'test': ['CMD-SHELL', 'exit 0'],
                        'interval': '30s',
                        'timeout': '10s',
                        'retries': 3
                    }
                }
            )

    def _check_root_user(self, service: str, config: Dict[str, Any]):
        """检查是否以 root 用户运行"""
        user = config.get('user')
        if not user:
            image = config.get('image', '') or ''
            risky_images = ['nginx', 'node', 'python', 'redis', 'postgres', 'mysql', 'mongo']
            if any(img in image.lower() for img in risky_images):
                self._add_risk(
                    level='medium',
                    category='security',
                    service=service,
                    message="未指定非 root 用户运行",
                    suggestion="使用 user: \"1000:1000\" 或在 Dockerfile 中创建非特权用户",
                    fix_patch={
                        'type': 'add_user',
                        'service': service,
                        'user': '1000:1000'
                    }
                )

    def _check_excessive_caps(self, service: str, config: Dict[str, Any]):
        """检查过多的 capabilities"""
        cap_add = config.get('cap_add', []) or []
        dangerous_caps = ['ALL', 'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'DAC_READ_SEARCH']
        for cap in cap_add:
            if cap in dangerous_caps:
                self._add_risk(
                    level='high',
                    category='security',
                    service=service,
                    message=f"添加了危险的 capability: {cap}",
                    suggestion=f"移除 {cap}，仅授予容器绝对必要的 capabilities",
                    fix_patch={
                        'type': 'remove_cap',
                        'service': service,
                        'cap': cap
                    }
                )

    def format_report(self, risks: List[Dict[str, Any]]) -> str:
        """格式化风险报告"""
        lines: List[str] = []
        lines.append("配置风险分析报告")
        lines.append("=" * 70)

        if not risks:
            lines.append("\n✅ 未发现明显的配置风险")
            return "\n".join(lines)

        by_level: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in risks:
            by_level[r['level']].append(r)

        lines.append(f"\n总计发现 {len(risks)} 个风险项:")
        for level in ['critical', 'high', 'medium', 'low']:
            if level in by_level:
                lines.append(f"  {self.RISK_LEVELS[level]}: {len(by_level[level])} 个")

        lines.append("\n" + "-" * 70)
        for r in risks:
            level_str = self.RISK_LEVELS[r['level']]
            lines.append(f"\n{level_str} [{r['category']}] {r['service']}")
            lines.append(f"  📝 问题: {r['message']}")
            lines.append(f"  💡 建议: {r['suggestion']}")
            if r['fix_patch']:
                lines.append(f"  🔧 支持自动修复: 是")

        return "\n".join(lines)


# =============================================================================
# 5. 资源估算模块
# =============================================================================

class ResourceEstimator:
    """资源估算器"""

    DEFAULT_CPU_THRESHOLD = 4.0
    DEFAULT_MEM_THRESHOLD = "8g"

    @staticmethod
    def parse_cpu(value: Any) -> Optional[float]:
        """解析 CPU 配额为核数"""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            value = value.strip().lower()
            if value.endswith('m'):
                try:
                    return float(value[:-1]) / 1000.0
                except ValueError:
                    return None
            try:
                return float(value)
            except ValueError:
                return None
        return None

    @staticmethod
    def parse_memory(value: Any) -> Optional[float]:
        """解析内存为 MB"""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value) / (1024 * 1024)
        if isinstance(value, str):
            value = value.strip().lower()
            units = {
                'b': 1 / (1024 * 1024),
                'k': 1 / 1024,
                'kb': 1 / 1024,
                'm': 1,
                'mb': 1,
                'g': 1024,
                'gb': 1024,
                't': 1024 * 1024,
                'tb': 1024 * 1024
            }
            for suffix, mult in sorted(units.items(), key=lambda x: -len(x[0])):
                if value.endswith(suffix):
                    try:
                        num = float(value[:-len(suffix)])
                        return num * mult
                    except ValueError:
                        return None
            try:
                return float(value) / (1024 * 1024)
            except ValueError:
                return None
        return None

    @staticmethod
    def format_memory(mb: float) -> str:
        """格式化内存显示"""
        if mb >= 1024:
            return f"{mb / 1024:.2f} GB"
        return f"{mb:.2f} MB"

    def _parse_custom_comments(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """从 labels 或自定义字段解析资源注释"""
        result = {'cpu': None, 'memory': None}
        labels = config.get('labels', {}) or {}

        label_items: List[Tuple[str, Any]] = []
        if isinstance(labels, dict):
            label_items = list(labels.items())
        elif isinstance(labels, list):
            for item in labels:
                if isinstance(item, str) and '=' in item:
                    k, v = item.split('=', 1)
                    label_items.append((k, v))

        for key, value in label_items:
            if 'resource' in key.lower() or 'estimate' in key.lower():
                if 'cpu' in key.lower():
                    result['cpu'] = self.parse_cpu(value)
                elif 'mem' in key.lower():
                    result['memory'] = self.parse_memory(value)

        return result

    def analyze(self, services: Dict[str, Dict[str, Any]],
                cpu_threshold: Optional[float] = None,
                mem_threshold_mb: Optional[float] = None) -> Dict[str, Any]:
        """分析资源需求"""
        cpu_threshold = cpu_threshold or self.DEFAULT_CPU_THRESHOLD
        mem_threshold_mb = mem_threshold_mb or self.parse_memory(self.DEFAULT_MEM_THRESHOLD)

        service_resources: Dict[str, Dict[str, Any]] = {}
        by_network: Dict[str, List[str]] = defaultdict(list)
        total_cpu_limit = 0.0
        total_cpu_reservation = 0.0
        total_mem_limit_mb = 0.0
        total_mem_reservation_mb = 0.0
        over_threshold: List[Dict[str, Any]] = []

        for name, config in services.items():
            deploy = config.get('deploy', {}) or {}
            resources = deploy.get('resources', {}) or {}
            limits = resources.get('limits', {}) or {}
            reservations = resources.get('reservations', {}) or {}

            custom = self._parse_custom_comments(config)

            cpu_limit = self.parse_cpu(limits.get('cpus')) or custom['cpu']
            cpu_reservation = self.parse_cpu(reservations.get('cpus')) or custom['cpu']
            mem_limit = self.parse_memory(limits.get('memory')) or custom['memory']
            mem_reservation = self.parse_memory(reservations.get('memory')) or custom['memory']

            if cpu_limit:
                total_cpu_limit += cpu_limit
            if cpu_reservation:
                total_cpu_reservation += cpu_reservation
            if mem_limit:
                total_mem_limit_mb += mem_limit
            if mem_reservation:
                total_mem_reservation_mb += mem_reservation

            if cpu_limit and cpu_limit > cpu_threshold:
                over_threshold.append({
                    'service': name,
                    'type': 'cpu_limit',
                    'value': cpu_limit,
                    'threshold': cpu_threshold
                })
            if mem_limit and mem_limit > mem_threshold_mb:
                over_threshold.append({
                    'service': name,
                    'type': 'memory_limit',
                    'value': mem_limit,
                    'threshold': mem_threshold_mb
                })

            networks = config.get('networks', []) or []
            if isinstance(networks, dict):
                net_list = list(networks.keys())
            elif isinstance(networks, list):
                net_list = []
                for n in networks:
                    if isinstance(n, str):
                        net_list.append(n)
                    elif isinstance(n, dict):
                        net_list.extend(n.keys())
            else:
                net_list = ['default']

            if not net_list:
                net_list = ['default']

            for net in net_list:
                by_network[net].append(name)

            service_resources[name] = {
                'cpu_limit': cpu_limit,
                'cpu_reservation': cpu_reservation,
                'mem_limit_mb': mem_limit,
                'mem_reservation_mb': mem_reservation,
                'has_resources': any([cpu_limit, cpu_reservation, mem_limit, mem_reservation]),
                'custom_estimate': any(custom.values())
            }

        return {
            'service_resources': service_resources,
            'by_network': dict(by_network),
            'totals': {
                'cpu_limit': total_cpu_limit,
                'cpu_reservation': total_cpu_reservation,
                'mem_limit_mb': total_mem_limit_mb,
                'mem_reservation_mb': total_mem_reservation_mb
            },
            'thresholds': {
                'cpu': cpu_threshold,
                'memory_mb': mem_threshold_mb
            },
            'over_threshold': over_threshold
        }

    def format_report(self, analysis: Dict[str, Any]) -> str:
        """格式化资源报告"""
        lines: List[str] = []
        lines.append("资源估算报告")
        lines.append("=" * 80)

        lines.append("\n📊 服务资源配置:")
        header = f"{'服务':<20} {'CPU 限制':<15} {'CPU 预留':<15} {'内存限制':<18} {'内存预留':<18}"
        lines.append(header)
        lines.append("-" * 90)

        for svc in sorted(analysis['service_resources'].keys()):
            res = analysis['service_resources'][svc]
            cpu_lim = f"{res['cpu_limit']:.2f} 核" if res['cpu_limit'] else '未设置'
            cpu_res = f"{res['cpu_reservation']:.2f} 核" if res['cpu_reservation'] else '未设置'
            mem_lim = self.format_memory(res['mem_limit_mb']) if res['mem_limit_mb'] else '未设置'
            mem_res = self.format_memory(res['mem_reservation_mb']) if res['mem_reservation_mb'] else '未设置'
            tag = ' *' if res.get('custom_estimate') else ''
            lines.append(f"{svc:<20} {cpu_lim:<15} {cpu_res:<15} {mem_lim:<18} {mem_res:<18}{tag}")

        lines.append("\n📈 资源汇总:")
        totals = analysis['totals']
        lines.append(f"  CPU 限制总计: {totals['cpu_limit']:.2f} 核")
        lines.append(f"  CPU 预留总计: {totals['cpu_reservation']:.2f} 核")
        lines.append(f"  内存限制总计: {self.format_memory(totals['mem_limit_mb'])}")
        lines.append(f"  内存预留总计: {self.format_memory(totals['mem_reservation_mb'])}")

        if analysis['over_threshold']:
            lines.append("\n🚨 超过阈值警告:")
            for item in analysis['over_threshold']:
                if item['type'] == 'cpu_limit':
                    lines.append(f"  ⚠️  服务 {item['service']}: CPU 限制 {item['value']:.2f} 核 > 阈值 {item['threshold']:.2f} 核")
                else:
                    lines.append(f"  ⚠️  服务 {item['service']}: 内存限制 {self.format_memory(item['value'])} > 阈值 {self.format_memory(item['threshold'])}")

        lines.append("\n🌐 按网络分组的服务:")
        for net in sorted(analysis['by_network'].keys()):
            services_list = analysis['by_network'][net]
            lines.append(f"\n  📡 {net}:")
            for svc in sorted(services_list):
                lines.append(f"      • {svc}")

        return "\n".join(lines)


# =============================================================================
# 6. 报告与修复建议模块
# =============================================================================

class ReportGenerator:
    """Markdown 报告生成器"""

    def __init__(self, parser: ComposeParser):
        self.parser = parser

    def generate_markdown(self,
                          dep_analyzer: DependencyAnalyzer,
                          port_analysis: Dict[str, Any],
                          risks: List[Dict[str, Any]],
                          resource_analysis: Dict[str, Any],
                          compose_files: List[str]) -> str:
        """生成完整的 Markdown 报告"""
        services = self.parser.get_services()
        md: List[str] = []

        md.append("# Docker Compose 配置分析报告")
        md.append("")
        md.append(f"> 生成时间: {self._current_time()}")
        md.append(f"> 分析文件: {', '.join(compose_files)}")
        md.append(f"> 服务数量: {len(services)}")
        md.append("")

        # 1. 概览
        md.append("## 📋 概览")
        md.append("")
        cycles = dep_analyzer.detect_cycles()
        port_issues = len(port_analysis['conflicts']) + len(port_analysis['container_conflicts']) + len(port_analysis['system_conflicts'])

        md.append("| 指标 | 数值 |")
        md.append("|------|------|")
        md.append(f"| 服务总数 | {len(services)} |")
        md.append(f"| 网络数 | {len(self.parser.get_networks()) or 1} |")
        md.append(f"| 数据卷数 | {len(self.parser.get_volumes())} |")
        md.append(f"| 循环依赖 | {len(cycles)} |")
        md.append(f"| 端口问题 | {port_issues} |")
        md.append(f"| 配置风险 | {len(risks)} |")
        md.append("")

        # 2. 依赖图
        md.append("## 🔗 服务依赖图")
        md.append("")
        md.append("### ASCII 可视化")
        md.append("")
        md.append("```")
        md.append(dep_analyzer.to_ascii_graph())
        md.append("```")
        md.append("")

        if cycles:
            md.append("### ⚠️ 循环依赖检测")
            md.append("")
            for cycle in cycles:
                md.append(f"- **循环链路**: `{' → '.join(cycle)} → {cycle[0]}`")
            md.append("")

        topo = dep_analyzer.topological_sort()
        md.append("### 🚀 建议启动顺序")
        md.append("")
        md.append(" → ".join(f"`{s}`" for s in topo))
        md.append("")

        # 3. 端口分析
        md.append("## 🚪 端口映射分析")
        md.append("")
        md.append("### 端口映射表")
        md.append("")
        md.append("| 服务 | 宿主机地址 | 宿主机端口 | 容器端口 | 协议 |")
        md.append("|------|-----------|-----------|---------|------|")
        for p in port_analysis['all_ports']:
            md.append(f"| {p['service']} | {p['host_ip']} | {p['published']} | {p['target']} | {p['protocol']} |")
        md.append("")

        all_port_issues = (port_analysis['conflicts'] + port_analysis['container_conflicts'] +
                           port_analysis['range_overlaps'] + port_analysis['system_conflicts'])
        if all_port_issues:
            md.append("### ⚠️ 端口问题")
            md.append("")
            for issue in all_port_issues:
                icon = "🚨" if 'conflict' in issue.get('type', '') or 'in_use' in issue.get('type', '') else "⚠️"
                md.append(f"- {icon} {issue['details']}")
            md.append("")

        # 4. 风险分析
        md.append("## ⚠️ 配置风险分析")
        md.append("")

        if risks:
            md.append("### 风险统计")
            md.append("")
            level_counts: Dict[str, int] = defaultdict(int)
            for r in risks:
                level_counts[r['level']] += 1
            md.append("| 级别 | 数量 |")
            md.append("|------|------|")
            for level in ['critical', 'high', 'medium', 'low']:
                icon = RiskChecker.RISK_LEVELS[level]
                md.append(f"| {icon} | {level_counts.get(level, 0)} |")
            md.append("")

            md.append("### 风险详情")
            md.append("")
            for r in risks:
                level_str = RiskChecker.RISK_LEVELS[r['level']]
                fixable = "✅ 可自动修复" if r.get('fix_patch') else "❌ 需手动修复"
                md.append(f"#### {level_str} - {r['service']} ({r['category']})")
                md.append("")
                md.append(f"- **问题**: {r['message']}")
                md.append(f"- **建议**: {r['suggestion']}")
                md.append(f"- **修复**: {fixable}")
                md.append("")
        else:
            md.append("✅ 未发现明显的配置风险")
            md.append("")

        # 5. 资源估算
        md.append("## 💻 资源估算")
        md.append("")
        md.append("### 服务资源配置")
        md.append("")
        md.append("| 服务 | CPU 限制 | CPU 预留 | 内存限制 | 内存预留 |")
        md.append("|------|---------|---------|---------|---------|")
        estimator = ResourceEstimator()
        for svc in sorted(resource_analysis['service_resources'].keys()):
            res = resource_analysis['service_resources'][svc]
            cpu_lim = f"{res['cpu_limit']:.2f} 核" if res['cpu_limit'] else '-'
            cpu_res = f"{res['cpu_reservation']:.2f} 核" if res['cpu_reservation'] else '-'
            mem_lim = estimator.format_memory(res['mem_limit_mb']) if res['mem_limit_mb'] else '-'
            mem_res = estimator.format_memory(res['mem_reservation_mb']) if res['mem_reservation_mb'] else '-'
            md.append(f"| {svc} | {cpu_lim} | {cpu_res} | {mem_lim} | {mem_res} |")
        md.append("")

        totals = resource_analysis['totals']
        md.append("### 资源汇总")
        md.append("")
        md.append(f"- **CPU 限制总计**: {totals['cpu_limit']:.2f} 核")
        md.append(f"- **CPU 预留总计**: {totals['cpu_reservation']:.2f} 核")
        md.append(f"- **内存限制总计**: {estimator.format_memory(totals['mem_limit_mb'])}")
        md.append(f"- **内存预留总计**: {estimator.format_memory(totals['mem_reservation_mb'])}")
        md.append("")

        if resource_analysis['over_threshold']:
            md.append("### 🚨 超阈值警告")
            md.append("")
            for item in resource_analysis['over_threshold']:
                if item['type'] == 'cpu_limit':
                    md.append(f"- ⚠️ 服务 **{item['service']}**: CPU 限制 {item['value']:.2f} 核 超过阈值 {item['threshold']:.2f} 核")
                else:
                    md.append(f"- ⚠️ 服务 **{item['service']}**: 内存限制 {estimator.format_memory(item['value'])} 超过阈值 {estimator.format_memory(item['threshold'])}")
            md.append("")

        md.append("### 按网络分组")
        md.append("")
        for net in sorted(resource_analysis['by_network'].keys()):
            svcs = resource_analysis['by_network'][net]
            md.append(f"- **{net}**: {', '.join(sorted(svcs))}")
        md.append("")

        # 6. 优化建议
        md.append("## 💡 优化建议")
        md.append("")
        suggestions = self._generate_suggestions(risks, cycles, port_analysis, resource_analysis)
        for i, s in enumerate(suggestions, 1):
            md.append(f"{i}. {s}")
        md.append("")

        return "\n".join(md)

    @staticmethod
    def _current_time() -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _generate_suggestions(risks: List[Dict[str, Any]],
                              cycles: List[List[str]],
                              port_analysis: Dict[str, Any],
                              resource_analysis: Dict[str, Any]) -> List[str]:
        suggestions: List[str] = []

        # 循环依赖
        if cycles:
            suggestions.append("**解决循环依赖**: 检测到循环依赖，需要重构服务关系。建议将公共依赖抽取为独立组件，或使用事件驱动架构解耦。")

        # 端口
        port_issue_count = (len(port_analysis['conflicts']) + len(port_analysis['container_conflicts']) +
                            len(port_analysis['system_conflicts']))
        if port_issue_count > 0:
            suggestions.append(f"**修复端口问题**: 共发现 {port_issue_count} 个端口相关问题，请修正映射冲突和系统已占用端口。")

        # 风险分类建议
        if any(r['level'] == 'critical' for r in risks):
            suggestions.append("**立即处理严重风险**: 存在严重安全风险（如 Docker socket 挂载、特权模式），请立即修复。")

        if any(r['level'] == 'high' for r in risks):
            suggestions.append("**处理高危风险**: 明文密码和危险 capabilities 可能导致安全漏洞，建议使用 Docker Secrets 管理敏感信息。")

        if any(r['category'] == 'reliability' for r in risks):
            suggestions.append("**提升可靠性**: 为所有服务配置重启策略和健康检查，确保服务故障时能够自动恢复。")

        if any(r['category'] == 'stability' for r in risks):
            suggestions.append("**使用固定镜像标签**: 避免使用 latest 标签，指定具体版本号以保证部署一致性。")

        # 资源建议
        no_resource = [s for s, r in resource_analysis['service_resources'].items() if not r['has_resources']]
        if no_resource:
            suggestions.append(f"**设置资源限制**: 服务 {', '.join(no_resource)} 未配置 CPU/内存限制，建议添加 resources 配置防止资源耗尽。")

        if resource_analysis['over_threshold']:
            suggestions.append("**评估资源需求**: 部分服务的资源限制超过建议阈值，请评估是否真的需要这么多资源。")

        if not suggestions:
            suggestions.append("当前配置状态良好，请保持定期检查以确保配置安全性和可靠性。")

        return suggestions


class FixGenerator:
    """自动修复补丁生成器"""

    @staticmethod
    def generate_patch(risks: List[Dict[str, Any]], original_config: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """生成修复后的配置和应用的修复列表"""
        fixed_config = copy.deepcopy(original_config)
        applied_fixes: List[str] = []

        for risk in risks:
            patch = risk.get('fix_patch')
            if not patch:
                continue

            patch_type = patch['type']
            service = patch['service']
            services_config = fixed_config.setdefault('services', {})

            if service not in services_config:
                continue

            svc_config = services_config[service]

            if patch_type == 'environment':
                env = svc_config.get('environment', {})
                key = patch['key']
                new_val = patch['value']
                if isinstance(env, dict):
                    if key in env:
                        env[key] = new_val
                elif isinstance(env, list):
                    new_env = []
                    for item in env:
                        if isinstance(item, str) and item.startswith(f"{key}="):
                            new_env.append(f"{key}={new_val}")
                        else:
                            new_env.append(item)
                    svc_config['environment'] = new_env
                applied_fixes.append(f"[安全] {service}: 将环境变量 {key} 改为引用形式")

            elif patch_type == 'add_restart':
                svc_config['restart'] = patch['restart']
                applied_fixes.append(f"[可靠性] {service}: 添加 restart: {patch['restart']}")

            elif patch_type == 'add_healthcheck':
                svc_config['healthcheck'] = patch['healthcheck']
                applied_fixes.append(f"[可观测性] {service}: 添加 healthcheck 配置")

            elif patch_type == 'remove_privileged':
                if 'privileged' in svc_config:
                    del svc_config['privileged']
                    applied_fixes.append(f"[安全] {service}: 移除 privileged: true（请手动验证功能）")

            elif patch_type == 'add_user':
                if 'user' not in svc_config:
                    svc_config['user'] = patch['user']
                    applied_fixes.append(f"[安全] {service}: 添加 user: {patch['user']}")

            elif patch_type == 'remove_cap':
                cap_add = svc_config.get('cap_add', [])
                if isinstance(cap_add, list):
                    if patch['cap'] in cap_add:
                        cap_add.remove(patch['cap'])
                        applied_fixes.append(f"[安全] {service}: 移除危险 capability: {patch['cap']}")

        return fixed_config, applied_fixes

    @staticmethod
    def generate_diff(original: Dict[str, Any], fixed: Dict[str, Any]) -> str:
        """生成配置 diff（简化版）"""
        orig_services = original.get('services', {})
        fixed_services = fixed.get('services', {})
        diff_lines: List[str] = []

        all_services = set(orig_services.keys()) | set(fixed_services.keys())
        for svc in sorted(all_services):
            orig_svc = orig_services.get(svc, {})
            fixed_svc = fixed_services.get(svc, {})

            all_keys = set(orig_svc.keys()) | set(fixed_svc.keys())
            changed = False
            for key in sorted(all_keys):
                orig_val = orig_svc.get(key)
                fixed_val = fixed_svc.get(key)
                if orig_val != fixed_val:
                    changed = True
                    break

            if changed:
                diff_lines.append(f"--- services.{svc}")
                diff_lines.append(f"+++ services.{svc}")
                for key in sorted(all_keys):
                    orig_val = orig_svc.get(key)
                    fixed_val = fixed_svc.get(key)
                    if orig_val != fixed_val:
                        if orig_val is not None:
                            diff_lines.append(f"- {key}: {yaml.safe_dump({key: orig_val}, default_flow_style=True).strip()}")
                        if fixed_val is not None:
                            diff_lines.append(f"+ {key}: {yaml.safe_dump({key: fixed_val}, default_flow_style=True).strip()}")
                diff_lines.append("")

        return "\n".join(diff_lines)


# =============================================================================
# 7. 主 CLI 入口
# =============================================================================

def cmd_analyze(args):
    """analyze 子命令：完整分析"""
    compose_files = args.compose_file
    if args.override:
        compose_files.extend(args.override)

    parser = ComposeParser()
    config = parser.parse(compose_files)
    services = parser.get_services()

    if not services:
        print("⚠️  未找到任何服务配置")
        return 1

    print("=" * 70)
    print("Docker Compose 配置分析工具")
    print("=" * 70)
    print(f"分析文件: {', '.join(compose_files)}")
    print(f"服务数量: {len(services)}")
    print()

    # 依赖分析
    print("-" * 70)
    dep_analyzer = DependencyAnalyzer(services)
    print(dep_analyzer.to_ascii_graph())
    print()

    # DOT 输出
    if args.dot:
        dot_content = dep_analyzer.to_dot()
        with open(args.dot, 'w', encoding='utf-8') as f:
            f.write(dot_content)
        print(f"✅ Graphviz DOT 文件已保存: {args.dot}")
        print(f"   使用方法: dot -Tpng {args.dot} -o graph.png")
        print()

    # 端口分析
    print("-" * 70)
    port_checker = PortChecker()
    port_analysis = port_checker.analyze(services, check_system=not args.no_system_ports)
    print(port_checker.format_report(port_analysis))
    print()

    # 风险分析
    print("-" * 70)
    risk_checker = RiskChecker()
    risks = risk_checker.analyze(services)
    print(risk_checker.format_report(risks))
    print()

    # 资源估算
    print("-" * 70)
    estimator = ResourceEstimator()
    cpu_thresh = args.cpu_threshold if args.cpu_threshold else None
    mem_thresh = estimator.parse_memory(args.mem_threshold) if args.mem_threshold else None
    resource_analysis = estimator.analyze(services, cpu_thresh, mem_thresh)
    print(estimator.format_report(resource_analysis))
    print()

    # Markdown 报告
    if args.report:
        report_gen = ReportGenerator(parser)
        md_content = report_gen.generate_markdown(
            dep_analyzer, port_analysis, risks, resource_analysis, compose_files
        )
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"✅ Markdown 报告已保存: {args.report}")
        print()

    # 自动修复
    if args.fix:
        print("-" * 70)
        print("🔧 生成自动修复补丁...")
        fix_gen = FixGenerator()
        fixed_config, applied = fix_gen.generate_patch(risks, config)

        if applied:
            print(f"\n✅ 已应用 {len(applied)} 个修复:")
            for fix in applied:
                print(f"   • {fix}")

            diff = fix_gen.generate_diff(config, fixed_config)
            if args.fix_output:
                with open(args.fix_output, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(fixed_config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                print(f"\n✅ 修复后的配置已保存: {args.fix_output}")
            else:
                base, ext = os.path.splitext(compose_files[0])
                output_file = f"{base}_fixed{ext}"
                with open(output_file, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(fixed_config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                print(f"\n✅ 修复后的配置已保存: {output_file}")

            if diff:
                patch_file = args.fix_output.replace(os.path.splitext(args.fix_output)[1], '.patch') if args.fix_output else 'fix.patch'
                with open(patch_file, 'w', encoding='utf-8') as f:
                    f.write(diff)
                print(f"✅ 补丁文件已保存: {patch_file}")
        else:
            print("\nℹ️  没有可以自动修复的问题")

    # 退出码
    has_critical = any(r['level'] in ('critical', 'high') for r in risks)
    has_port_issues = (port_analysis['conflicts'] or port_analysis['system_conflicts'])
    has_cycles = dep_analyzer.detect_cycles()

    if has_critical or has_port_issues or has_cycles:
        return 1
    return 0


def cmd_ports(args):
    """ports 子命令：端口检查"""
    compose_files = [args.compose_file]
    if args.override:
        compose_files.extend(args.override)

    parser = ComposeParser()
    config = parser.parse(compose_files)
    services = parser.get_services()

    port_checker = PortChecker()
    analysis = port_checker.analyze(services, check_system=not args.no_system_ports)
    print(port_checker.format_report(analysis))

    has_issues = (analysis['conflicts'] or analysis['system_conflicts'] or
                  analysis['container_conflicts'] or analysis['range_overlaps'])
    return 1 if (analysis['conflicts'] or analysis['system_conflicts']) else 0


def cmd_risks(args):
    """risks 子命令：风险检查"""
    compose_files = [args.compose_file]
    if args.override:
        compose_files.extend(args.override)

    parser = ComposeParser()
    config = parser.parse(compose_files)
    services = parser.get_services()

    risk_checker = RiskChecker()
    risks = risk_checker.analyze(services)
    print(risk_checker.format_report(risks))

    if args.fix:
        print("\n" + "-" * 70)
        print("🔧 生成自动修复补丁...")
        fix_gen = FixGenerator()
        fixed_config, applied = fix_gen.generate_patch(risks, config)

        if applied:
            print(f"\n✅ 已应用 {len(applied)} 个修复:")
            for fix in applied:
                print(f"   • {fix}")

            base, ext = os.path.splitext(compose_files[0])
            output_file = f"{base}_fixed{ext}"
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump(fixed_config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"\n✅ 修复后的配置已保存: {output_file}")
        else:
            print("\nℹ️  没有可以自动修复的问题")

    return 1 if any(r['level'] in ('critical', 'high') for r in risks) else 0


def cmd_graph(args):
    """graph 子命令：依赖图"""
    compose_files = [args.compose_file]
    if args.override:
        compose_files.extend(args.override)

    parser = ComposeParser()
    config = parser.parse(compose_files)
    services = parser.get_services()

    dep_analyzer = DependencyAnalyzer(services)

    if args.format == 'ascii':
        print(dep_analyzer.to_ascii_graph())
    elif args.format == 'dot':
        print(dep_analyzer.to_dot())

    if args.output:
        if args.format == 'dot':
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(dep_analyzer.to_dot())
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(dep_analyzer.to_ascii_graph())
        print(f"\n✅ 已保存到: {args.output}")

    cycles = dep_analyzer.detect_cycles()
    return 1 if cycles else 0


def cmd_resources(args):
    """resources 子命令：资源估算"""
    compose_files = [args.compose_file]
    if args.override:
        compose_files.extend(args.override)

    parser = ComposeParser()
    config = parser.parse(compose_files)
    services = parser.get_services()

    estimator = ResourceEstimator()
    cpu_thresh = args.cpu_threshold if args.cpu_threshold else None
    mem_thresh = estimator.parse_memory(args.mem_threshold) if args.mem_threshold else None
    analysis = estimator.analyze(services, cpu_thresh, mem_thresh)
    print(estimator.format_report(analysis))

    return 1 if analysis['over_threshold'] else 0


def main():
    parser = argparse.ArgumentParser(
        prog='composecheck',
        description='Docker Compose 配置分析 CLI 工具 - 检查端口冲突、依赖关系、配置风险等',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python composecheck.py analyze docker-compose.yml --dot graph.dot --report report.md
  python composecheck.py analyze docker-compose.yml docker-compose.override.yml --fix
  python composecheck.py ports docker-compose.yml
  python composecheck.py risks docker-compose.yml --fix
  python composecheck.py graph docker-compose.yml --format dot --output graph.dot
  python composecheck.py resources docker-compose.yml --cpu-threshold 8 --mem-threshold 16g
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='可用命令')

    # analyze 子命令
    analyze_parser = subparsers.add_parser('analyze', help='完整分析（依赖图、端口、风险、资源）')
    analyze_parser.add_argument('compose_file', nargs='+', help='Compose 文件路径（可多个，按顺序合并）')
    analyze_parser.add_argument('-o', '--override', action='append', help='追加的 override 文件')
    analyze_parser.add_argument('--dot', help='输出 Graphviz DOT 文件路径')
    analyze_parser.add_argument('--report', help='输出 Markdown 报告文件路径')
    analyze_parser.add_argument('--fix', action='store_true', help='生成自动修复的配置')
    analyze_parser.add_argument('--fix-output', help='修复后配置的输出路径')
    analyze_parser.add_argument('--no-system-ports', action='store_true', help='不检查系统端口占用')
    analyze_parser.add_argument('--cpu-threshold', type=float, help='CPU 阈值（核数），默认 4')
    analyze_parser.add_argument('--mem-threshold', help='内存阈值（如 8g, 1024m），默认 8g')

    # ports 子命令
    ports_parser = subparsers.add_parser('ports', help='检查端口映射冲突')
    ports_parser.add_argument('compose_file', help='Compose 文件路径')
    ports_parser.add_argument('-o', '--override', action='append', help='追加的 override 文件')
    ports_parser.add_argument('--no-system-ports', action='store_true', help='不检查系统端口占用')

    # risks 子命令
    risks_parser = subparsers.add_parser('risks', help='检查配置风险')
    risks_parser.add_argument('compose_file', help='Compose 文件路径')
    risks_parser.add_argument('-o', '--override', action='append', help='追加的 override 文件')
    risks_parser.add_argument('--fix', action='store_true', help='生成自动修复的配置')

    # graph 子命令
    graph_parser = subparsers.add_parser('graph', help='生成服务依赖图')
    graph_parser.add_argument('compose_file', help='Compose 文件路径')
    graph_parser.add_argument('-o', '--override', action='append', help='追加的 override 文件')
    graph_parser.add_argument('--format', choices=['ascii', 'dot'], default='ascii', help='输出格式（默认 ascii）')
    graph_parser.add_argument('--output', '-O', help='输出文件路径')

    # resources 子命令
    resources_parser = subparsers.add_parser('resources', help='估算资源需求')
    resources_parser.add_argument('compose_file', help='Compose 文件路径')
    resources_parser.add_argument('-o', '--override', action='append', help='追加的 override 文件')
    resources_parser.add_argument('--cpu-threshold', type=float, help='CPU 阈值（核数），默认 4')
    resources_parser.add_argument('--mem-threshold', help='内存阈值（如 8g, 1024m），默认 8g')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == 'analyze':
            return cmd_analyze(args)
        elif args.command == 'ports':
            return cmd_ports(args)
        elif args.command == 'risks':
            return cmd_risks(args)
        elif args.command == 'graph':
            return cmd_graph(args)
        elif args.command == 'resources':
            return cmd_resources(args)
    except FileNotFoundError as e:
        print(f"❌ 错误: {e}", file=sys.stderr)
        return 1
    except yaml.YAMLError as e:
        print(f"❌ YAML 解析错误: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ 未知错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main() or 0)
