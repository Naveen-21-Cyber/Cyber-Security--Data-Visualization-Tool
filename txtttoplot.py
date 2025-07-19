import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import json
import re
from collections import Counter
import seaborn as sns


class CyberSecurityPlotCreator:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Text-to-Plot Creator")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2c3e50')
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Data storage
        self.current_data = None
        self.plot_history = []
        self.current_canvas = None
        
        # Cybersecurity plot templates (MOVE THIS BEFORE create_main_interface)
        self.plot_templates = {
            "Attack Timeline": self.create_attack_timeline,
            "Threat Distribution": self.create_threat_distribution,
            "Vulnerability Severity": self.create_vulnerability_chart,
            "Network Traffic Analysis": self.create_network_traffic,
            "Security Incidents": self.create_security_incidents,
            "Malware Detection": self.create_malware_detection,
            "Firewall Logs": self.create_firewall_logs,
            "User Access Patterns": self.create_access_patterns,
            "Threat Intelligence": self.create_threat_intelligence,
            "Compliance Status": self.create_compliance_status
        }
    
    # Create main interface
        self.create_main_interface()
        
    def configure_styles(self):
        """Configure custom styles for the application"""
        self.style.configure('Title.TLabel', 
                           foreground='#ecf0f1', 
                           background='#2c3e50',
                           font=('Arial', 16, 'bold'))
        
        self.style.configure('Cyber.TFrame', 
                           background='#34495e',
                           relief='raised',
                           borderwidth=2)
        
        self.style.configure('Cyber.TButton',
                           background='#e74c3c',
                           foreground='white',
                           font=('Arial', 10, 'bold'))
        
    def create_main_interface(self):
        """Create the main interface layout"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Cyber.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, 
                               text="🔒 Cybersecurity Data Visualization Tool", 
                               style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_data_input_tab()
        self.create_plot_config_tab()
        self.create_visualization_tab()
        self.create_analysis_tab()
        
    def create_data_input_tab(self):
        """Create data input and parsing tab"""
        input_frame = ttk.Frame(self.notebook)
        self.notebook.add(input_frame, text="📝 Data Input")
        
        # Input methods frame
        input_methods = ttk.LabelFrame(input_frame, text="Input Methods", padding=10)
        input_methods.pack(fill=tk.X, padx=10, pady=5)
        
        # Buttons for different input methods
        btn_frame = ttk.Frame(input_methods)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="Load Log File", 
                  command=self.load_log_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Load CSV", 
                  command=self.load_csv_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generate Sample Data", 
                  command=self.generate_sample_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Parse Text", 
                  command=self.parse_text_input).pack(side=tk.LEFT, padx=5)
        
        # Text input area
        text_frame = ttk.LabelFrame(input_frame, text="Text Input/Log Data", padding=10)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.text_input = scrolledtext.ScrolledText(text_frame, 
                                                   height=15, 
                                                   bg='#1a1a1a', 
                                                   fg='#00ff00',
                                                   insertbackground='#00ff00',
                                                   font=('Consolas', 10))
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        # Sample data button
        sample_frame = ttk.Frame(input_frame)
        sample_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(sample_frame, text="Insert Sample Firewall Logs", 
                  command=self.insert_sample_firewall_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(sample_frame, text="Insert Sample Attack Data", 
                  command=self.insert_sample_attack_data).pack(side=tk.LEFT, padx=5)
        
    def create_plot_config_tab(self):
        """Create plot configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="⚙ Plot Configuration")
        
        # Plot type selection
        type_frame = ttk.LabelFrame(config_frame, text="Plot Type", padding=10)
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.plot_type_var = tk.StringVar(value="Attack Timeline")
        plot_types = list(self.plot_templates.keys())
        
        for i, plot_type in enumerate(plot_types):
            row = i // 3
            col = i % 3
            ttk.Radiobutton(type_frame, text=plot_type, 
                           variable=self.plot_type_var, 
                           value=plot_type).grid(row=row, column=col, 
                                               sticky=tk.W, padx=10, pady=2)
        
        # Configuration options
        options_frame = ttk.LabelFrame(config_frame, text="Plot Options", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Color scheme
        ttk.Label(options_frame, text="Color Scheme:").grid(row=0, column=0, sticky=tk.W)
        self.color_var = tk.StringVar(value="Security Red")
        color_combo = ttk.Combobox(options_frame, textvariable=self.color_var,
                                  values=["Security Red", "Cyber Blue", "Hacker Green", 
                                         "Warning Orange", "Critical Purple"])
        color_combo.grid(row=0, column=1, padx=10, sticky=tk.W)
        
        # Plot size
        ttk.Label(options_frame, text="Plot Size:").grid(row=1, column=0, sticky=tk.W)
        self.size_var = tk.StringVar(value="Large")
        size_combo = ttk.Combobox(options_frame, textvariable=self.size_var,
                                 values=["Small", "Medium", "Large", "Extra Large"])
        size_combo.grid(row=1, column=1, padx=10, sticky=tk.W)
        
        # Animation
        self.animate_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Animated Plot", 
                       variable=self.animate_var).grid(row=2, column=0, sticky=tk.W)
        
        # Dark theme
        self.dark_theme_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Dark Theme", 
                       variable=self.dark_theme_var).grid(row=2, column=1, sticky=tk.W)
        
        # Generate button
        ttk.Button(config_frame, text="🔍 Generate Plot", 
                  command=self.generate_plot,
                  style='Cyber.TButton').pack(pady=20)
        
    def create_visualization_tab(self):
        """Create visualization display tab"""
        viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(viz_frame, text="📊 Visualization")
        
        # Control buttons
        control_frame = ttk.Frame(viz_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="Save Plot", 
                  command=self.save_plot).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Data", 
                  command=self.export_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Plot", 
                  command=self.clear_plot).pack(side=tk.LEFT, padx=5)
        
        # Plot display area
        self.plot_frame = ttk.Frame(viz_frame)
        self.plot_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def create_analysis_tab(self):
        """Create analysis and insights tab"""
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="🔍 Analysis")
        
        # Analysis results
        results_frame = ttk.LabelFrame(analysis_frame, text="Analysis Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.analysis_text = scrolledtext.ScrolledText(results_frame, 
                                                      height=20,
                                                      bg='#1a1a1a',
                                                      fg='#ffffff',
                                                      font=('Consolas', 10))
        self.analysis_text.pack(fill=tk.BOTH, expand=True)
        
        # Analysis buttons
        btn_frame = ttk.Frame(analysis_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Analyze Data", 
                  command=self.analyze_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generate Report", 
                  command=self.generate_report).pack(side=tk.LEFT, padx=5)
        
    def load_log_file(self):
        """Load log file for analysis"""
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", ".log"), ("Text files", ".txt"), ("All files", ".")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.text_input.delete(1.0, tk.END)
                    self.text_input.insert(1.0, content)
                messagebox.showinfo("Success", "Log file loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def load_csv_file(self):
        """Load CSV file for analysis"""
        file_path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV files", ".csv"), ("All files", ".*")]
        )
        
        if file_path:
            try:
                self.current_data = pd.read_csv(file_path)
                self.text_input.delete(1.0, tk.END)
                self.text_input.insert(1.0, f"CSV loaded: {file_path}\n")
                self.text_input.insert(tk.END, f"Shape: {self.current_data.shape}\n")
                self.text_input.insert(tk.END, f"Columns: {list(self.current_data.columns)}\n")
                self.text_input.insert(tk.END, self.current_data.head().to_string())
                messagebox.showinfo("Success", "CSV file loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load CSV: {str(e)}")
    
    def generate_sample_data(self):
        """Generate sample cybersecurity data"""
        # Generate sample attack data
        np.random.seed(42)
        dates = pd.date_range(start='2024-01-01', end='2024-12-31', freq='D')
        
        attack_types = ['DDoS', 'Malware', 'Phishing', 'SQL Injection', 'Brute Force', 'Ransomware']
        severities = ['Low', 'Medium', 'High', 'Critical']
        
        data = []
        for _ in range(1000):
            data.append({
                'timestamp': np.random.choice(dates),
                'attack_type': np.random.choice(attack_types),
                'severity': np.random.choice(severities),
                'source_ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'target_port': np.random.choice([80, 443, 22, 3389, 21, 23]),
                'blocked': np.random.choice([True, False], p=[0.7, 0.3])
            })
        
        self.current_data = pd.DataFrame(data)
        self.text_input.delete(1.0, tk.END)
        self.text_input.insert(1.0, "Sample cybersecurity data generated!\n")
        self.text_input.insert(tk.END, f"Records: {len(self.current_data)}\n")
        self.text_input.insert(tk.END, self.current_data.head().to_string())
        
    def insert_sample_firewall_logs(self):
        """Insert sample firewall log data"""
        sample_logs = """2024-01-15 10:23:45 BLOCK 192.168.1.100 -> 203.0.113.45:443 TCP
2024-01-15 10:24:12 ALLOW 192.168.1.101 -> 8.8.8.8:53 UDP
2024-01-15 10:25:33 BLOCK 203.0.113.67 -> 192.168.1.100:22 TCP
2024-01-15 10:26:01 BLOCK 198.51.100.89 -> 192.168.1.100:3389 TCP
2024-01-15 10:27:45 ALLOW 192.168.1.102 -> 172.16.0.1:80 TCP
2024-01-15 10:28:12 BLOCK 203.0.113.23 -> 192.168.1.100:445 TCP
2024-01-15 10:29:33 BLOCK 198.51.100.45 -> 192.168.1.100:135 TCP
2024-01-15 10:30:01 ALLOW 192.168.1.103 -> 172.217.12.46:443 TCP"""
        
        self.text_input.delete(1.0, tk.END)
        self.text_input.insert(1.0, sample_logs)
        
    def insert_sample_attack_data(self):
        """Insert sample attack data"""
        sample_attacks = """Attack Type: DDoS, Severity: High, Time: 2024-01-15 14:30:00, Source: 203.0.113.0/24
Attack Type: Malware, Severity: Critical, Time: 2024-01-15 15:45:00, Source: 198.51.100.45
Attack Type: Phishing, Severity: Medium, Time: 2024-01-15 16:20:00, Source: phishing@example.com
Attack Type: SQL Injection, Severity: High, Time: 2024-01-15 17:10:00, Source: 192.0.2.45
Attack Type: Brute Force, Severity: Medium, Time: 2024-01-15 18:00:00, Source: 203.0.113.67
Attack Type: Ransomware, Severity: Critical, Time: 2024-01-15 19:30:00, Source: 198.51.100.89"""
        
        self.text_input.delete(1.0, tk.END)
        self.text_input.insert(1.0, sample_attacks)
    
    def parse_text_input(self):
        """Parse text input for cybersecurity data"""
        text = self.text_input.get(1.0, tk.END).strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter some text to parse!")
            return
        
        try:
            parsed_data = self.parse_cybersecurity_text(text)
            self.current_data = pd.DataFrame(parsed_data)
            messagebox.showinfo("Success", f"Parsed {len(parsed_data)} records!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse text: {str(e)}")
    
    def parse_cybersecurity_text(self, text):
        """Parse cybersecurity text into structured data"""
        lines = text.split('\n')
        parsed_data = []
        
        for line in lines:
            if not line.strip():
                continue
                
            # Try to parse firewall logs
            firewall_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (BLOCK|ALLOW) (.+?) -> (.+?):(\d+) (TCP|UDP)', line)
            if firewall_match:
                timestamp, action, source_ip, dest_ip, port, protocol = firewall_match.groups()
                parsed_data.append({
                    'timestamp': pd.to_datetime(timestamp),
                    'type': 'Firewall',
                    'action': action,
                    'source_ip': source_ip,
                    'dest_ip': dest_ip,
                    'port': int(port),
                    'protocol': protocol
                })
                continue
            
            # Try to parse attack data
            attack_match = re.search(r'Attack Type: (.+?), Severity: (.+?), Time: (.+?), Source: (.+)', line)
            if attack_match:
                attack_type, severity, timestamp, source = attack_match.groups()
                parsed_data.append({
                    'timestamp': pd.to_datetime(timestamp),
                    'type': 'Attack',
                    'attack_type': attack_type,
                    'severity': severity,
                    'source': source
                })
                continue
            
            # Generic parsing for other formats
            if any(keyword in line.lower() for keyword in ['attack', 'malware', 'threat', 'vulnerability']):
                parsed_data.append({
                    'timestamp': datetime.now(),
                    'type': 'Generic',
                    'description': line.strip()
                })
        
        return parsed_data
    
    def get_color_palette(self):
        """Get color palette based on selected scheme"""
        palettes = {
            "Security Red": ['#e74c3c', '#c0392b', '#a93226', '#922b21', '#7b241c'],
            "Cyber Blue": ['#3498db', '#2980b9', '#2471a3', '#1f618d', '#1a5276'],
            "Hacker Green": ['#27ae60', '#239b56', '#1e8449', '#196f3d', '#145a32'],
            "Warning Orange": ['#f39c12', '#e67e22', '#d35400', '#ba4a00', '#a04000'],
            "Critical Purple": ['#9b59b6', '#8e44ad', '#7d3c98', '#6c3483', '#5b2c6f']
        }
        return palettes.get(self.color_var.get(), palettes["Security Red"])
    
    def get_plot_size(self):
        """Get plot size based on selection"""
        sizes = {
            "Small": (8, 6),
            "Medium": (10, 8),
            "Large": (12, 9),
            "Extra Large": (14, 10)
        }
        return sizes.get(self.size_var.get(), sizes["Large"])
    
    def generate_plot(self):
        """Generate the selected plot type"""
        if self.current_data is None:
            messagebox.showwarning("Warning", "Please load or generate data first!")
            return
        
        plot_type = self.plot_type_var.get()
        
        try:
            if plot_type in self.plot_templates:
                self.plot_templates[plot_type]()
            else:
                messagebox.showerror("Error", f"Plot type '{plot_type}' not implemented!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate plot: {str(e)}")
    
    def create_attack_timeline(self):
        """Create attack timeline visualization"""
        fig, ax = plt.subplots(figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Process data for timeline
        if 'timestamp' in self.current_data.columns:
            timeline_data = self.current_data.groupby(self.current_data['timestamp'].dt.date).size()
            
            ax.plot(timeline_data.index, timeline_data.values, 
                   color=self.get_color_palette()[0], linewidth=2, marker='o')
            ax.fill_between(timeline_data.index, timeline_data.values, 
                           alpha=0.3, color=self.get_color_palette()[0])
            
            ax.set_title('Security Incidents Timeline', fontsize=16, fontweight='bold')
            ax.set_xlabel('Date', fontsize=12)
            ax.set_ylabel('Number of Incidents', fontsize=12)
            ax.grid(True, alpha=0.3)
            
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            self.display_plot(fig)
    
    def create_threat_distribution(self):
        """Create threat distribution pie chart"""
        fig, ax = plt.subplots(figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Get threat distribution
        if 'attack_type' in self.current_data.columns:
            threat_counts = self.current_data['attack_type'].value_counts()
        elif 'type' in self.current_data.columns:
            threat_counts = self.current_data['type'].value_counts()
        else:
            threat_counts = pd.Series([30, 25, 20, 15], 
                                    index=['DDoS', 'Malware', 'Phishing', 'SQL Injection'])
        
        colors = self.get_color_palette()[:len(threat_counts)]
        
        wedges, texts, autotexts = ax.pie(threat_counts.values, 
                                         labels=threat_counts.index,
                                         autopct='%1.1f%%',
                                         colors=colors,
                                         explode=[0.05] * len(threat_counts))
        
        ax.set_title('Threat Distribution', fontsize=16, fontweight='bold')
        
        # Enhance text visibility
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        self.display_plot(fig)
    
    def create_vulnerability_chart(self):
        """Create vulnerability severity chart"""
        fig, ax = plt.subplots(figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Get severity distribution
        if 'severity' in self.current_data.columns:
            severity_counts = self.current_data['severity'].value_counts()
        else:
            severity_counts = pd.Series([40, 30, 20, 10], 
                                      index=['Low', 'Medium', 'High', 'Critical'])
        
        colors = self.get_color_palette()[:len(severity_counts)]
        bars = ax.bar(severity_counts.index, severity_counts.values, color=colors)
        
        ax.set_title('Vulnerability Severity Distribution', fontsize=16, fontweight='bold')
        ax.set_xlabel('Severity Level', fontsize=12)
        ax.set_ylabel('Count', fontsize=12)
        ax.grid(True, alpha=0.3)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontweight='bold')
        
        self.display_plot(fig)
    
    def create_network_traffic(self):
        """Create network traffic analysis chart"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Generate sample network traffic data
        hours = range(24)
        traffic_volume = np.random.normal(100, 20, 24)
        attack_volume = np.random.normal(10, 5, 24)
        
        # Traffic volume over time
        ax1.plot(hours, traffic_volume, label='Normal Traffic', 
                color=self.get_color_palette()[1], linewidth=2)
        ax1.plot(hours, attack_volume, label='Attack Traffic', 
                color=self.get_color_palette()[0], linewidth=2)
        ax1.fill_between(hours, traffic_volume, alpha=0.3, color=self.get_color_palette()[1])
        ax1.fill_between(hours, attack_volume, alpha=0.3, color=self.get_color_palette()[0])
        
        ax1.set_title('Network Traffic Analysis', fontweight='bold')
        ax1.set_xlabel('Hour of Day')
        ax1.set_ylabel('Traffic Volume (MB)')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Port usage distribution
        ports = [80, 443, 22, 3389, 21, 23]
        port_usage = np.random.randint(10, 100, len(ports))
        
        ax2.barh([f'Port {p}' for p in ports], port_usage, 
                color=self.get_color_palette()[:len(ports)])
        ax2.set_title('Port Usage Distribution', fontweight='bold')
        ax2.set_xlabel('Connection Count')
        
        plt.tight_layout()
        self.display_plot(fig)
    
    def create_security_incidents(self):
        """Create security incidents heatmap"""
        fig, ax = plt.subplots(figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Create sample incident data
        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        hours = range(24)
        
        # Generate incident matrix
        incident_matrix = np.random.poisson(2, (len(days), len(hours)))
        
        # Create heatmap
        im = ax.imshow(incident_matrix, cmap='Reds', aspect='auto')
        
        # Set ticks and labels
        ax.set_xticks(range(len(hours)))
        ax.set_xticklabels(hours)
        ax.set_yticks(range(len(days)))
        ax.set_yticklabels(days)
        
        ax.set_title('Security Incidents Heatmap', fontsize=16, fontweight='bold')
        ax.set_xlabel('Hour of Day', fontsize=12)
        ax.set_ylabel('Day of Week', fontsize=12)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Incident Count', rotation=270, labelpad=20)
        
        # Add text annotations
        for i in range(len(days)):
            for j in range(len(hours)):
                text = ax.text(j, i, incident_matrix[i, j],
                             ha="center", va="center", color="white", fontweight='bold')
        
        plt.tight_layout()
        self.display_plot(fig)
    
    def create_malware_detection(self):
        """Create malware detection trends"""
        fig, ax = plt.subplots(figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Generate malware detection data
        dates = pd.date_range(start='2024-01-01', periods=30, freq='D')
        detected = np.random.poisson(15, 30)
        quarantined = np.random.poisson(12, 30)
        removed = np.random.poisson(10, 30)
        
        ax.plot(dates, detected, label='Detected', color=self.get_color_palette()[0], 
               linewidth=2, marker='o')
        ax.plot(dates, quarantined, label='Quarantined', color=self.get_color_palette()[1], 
               linewidth=2, marker='s')
        ax.plot(dates, removed, label='Removed', color=self.get_color_palette()[2], 
               linewidth=2, marker='^')
        
        ax.set_title('Malware Detection Trends', fontsize=16, fontweight='bold')
        ax.set_xlabel('Date', fontsize=12)
        ax.set_ylabel('Count', fontsize=12)
        ax.legend()
        ax.grid(alpha=0.3)
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        self.display_plot(fig)
    
    def create_firewall_logs(self):
        """Create firewall log analysis"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Firewall action distribution
        if 'action' in self.current_data.columns:
            action_counts = self.current_data['action'].value_counts()
        else:
            action_counts = pd.Series([70, 30], index=['BLOCK', 'ALLOW'])
        
        colors = [self.get_color_palette()[0], self.get_color_palette()[2]]
        ax1.pie(action_counts.values, labels=action_counts.index, autopct='%1.1f%%',
               colors=colors, explode=[0.05, 0])
        ax1.set_title('Firewall Actions', fontweight='bold')
        
        # Protocol distribution
        if 'protocol' in self.current_data.columns:
            protocol_counts = self.current_data['protocol'].value_counts()
        else:
            protocol_counts = pd.Series([60, 40], index=['TCP', 'UDP'])
        
        ax2.bar(protocol_counts.index, protocol_counts.values, 
               color=self.get_color_palette()[:len(protocol_counts)])
        ax2.set_title('Protocol Distribution', fontweight='bold')
        ax2.set_ylabel('Count')
        
        plt.tight_layout()
        self.display_plot(fig)
    
    def create_access_patterns(self):
        """Create user access patterns visualization"""
        fig, ax = plt.subplots(figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Generate access pattern data
        hours = range(24)
        successful_logins = np.random.poisson(20, 24)
        failed_logins = np.random.poisson(5, 24)
        
        width = 0.35
        x = np.arange(len(hours))
        
        bars1 = ax.bar(x - width/2, successful_logins, width, 
                      label='Successful', color=self.get_color_palette()[2])
        bars2 = ax.bar(x + width/2, failed_logins, width,
                      label='Failed', color=self.get_color_palette()[0])
        
        ax.set_title('User Access Patterns', fontsize=16, fontweight='bold')
        ax.set_xlabel('Hour of Day', fontsize=12)
        ax.set_ylabel('Login Attempts', fontsize=12)
        ax.set_xticks(x)
        ax.set_xticklabels(hours)
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        # Add value labels on bars
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontsize=8)
        
        plt.tight_layout()
        self.display_plot(fig)
    
    def create_threat_intelligence(self):
        """Create threat intelligence dashboard"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Threat sources by country
        countries = ['China', 'Russia', 'USA', 'Germany', 'Brazil']
        threat_counts = np.random.randint(5, 50, len(countries))
        
        ax1.barh(countries, threat_counts, color=self.get_color_palette()[:len(countries)])
        ax1.set_title('Threat Sources by Country', fontweight='bold')
        ax1.set_xlabel('Threat Count')
        
        # Attack vectors
        vectors = ['Email', 'Web', 'Network', 'USB', 'Social']
        vector_counts = np.random.randint(10, 80, len(vectors))
        
        ax2.pie(vector_counts, labels=vectors, autopct='%1.1f%%',
               colors=self.get_color_palette()[:len(vectors)])
        ax2.set_title('Attack Vectors', fontweight='bold')
        
        # Threat severity over time
        days = range(1, 31)
        severity_data = np.random.randint(1, 100, 30)
        
        ax3.plot(days, severity_data, color=self.get_color_palette()[0], linewidth=2)
        ax3.fill_between(days, severity_data, alpha=0.3, color=self.get_color_palette()[0])
        ax3.set_title('Threat Severity Trend', fontweight='bold')
        ax3.set_xlabel('Day')
        ax3.set_ylabel('Severity Score')
        ax3.grid(True, alpha=0.3)
        
        # Top target ports
        ports = [80, 443, 22, 3389, 21, 23, 25, 53]
        port_attacks = np.random.randint(5, 100, len(ports))
        
        ax4.bar([f'Port {p}' for p in ports], port_attacks, 
               color=self.get_color_palette()[:len(ports)])
        ax4.set_title('Most Targeted Ports', fontweight='bold')
        ax4.set_ylabel('Attack Count')
        plt.setp(ax4.get_xticklabels(), rotation=45, ha='right')
        
        plt.tight_layout()
        self.display_plot(fig)
    
    def create_compliance_status(self):
        """Create compliance status visualization"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=self.get_plot_size())
        
        if self.dark_theme_var.get():
            plt.style.use('dark_background')
        
        # Compliance scores
        frameworks = ['NIST', 'ISO 27001', 'PCI DSS', 'GDPR', 'HIPAA']
        scores = np.random.randint(60, 100, len(frameworks))
        
        colors = [self.get_color_palette()[0] if score < 80 else self.get_color_palette()[2] 
                 for score in scores]
        
        bars = ax1.bar(frameworks, scores, color=colors)
        ax1.set_title('Compliance Scores', fontweight='bold')
        ax1.set_ylabel('Score (%)')
        ax1.set_ylim(0, 100)
        ax1.axhline(y=80, color='red', linestyle='--', alpha=0.7, label='Minimum Threshold')
        ax1.legend()
        
        # Add score labels
        for bar, score in zip(bars, scores):
            ax1.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                    f'{score}%', ha='center', va='bottom', fontweight='bold')
        
        plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')
        
        # Control implementation status
        controls = ['Access Control', 'Encryption', 'Monitoring', 'Backup', 'Training']
        implemented = [85, 92, 78, 95, 70]
        
        ax2.barh(controls, implemented, color=self.get_color_palette()[2])
        ax2.set_title('Security Controls Implementation', fontweight='bold')
        ax2.set_xlabel('Implementation Rate (%)')
        ax2.set_xlim(0, 100)
        
        # Add percentage labels
        for i, (control, rate) in enumerate(zip(controls, implemented)):
            ax2.text(rate + 1, i, f'{rate}%', va='center', fontweight='bold')
        
        plt.tight_layout()
        self.display_plot(fig)
    
    def display_plot(self, fig):
        """Display the plot in the visualization tab"""
        # Clear previous plot
        for widget in self.plot_frame.winfo_children():
            widget.destroy()
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, master=self.plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Store canvas reference
        self.current_canvas = canvas
        
        # Add to plot history
        self.plot_history.append({
            'type': self.plot_type_var.get(),
            'timestamp': datetime.now(),
            'figure': fig
        })
    
    def save_plot(self):
        """Save the current plot"""
        if self.current_canvas is None:
            messagebox.showwarning("Warning", "No plot to save!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", ".png"), ("PDF files", ".pdf"), 
                      ("SVG files", ".svg"), ("All files", ".*")]
        )
        
        if file_path:
            try:
                self.current_canvas.figure.savefig(file_path, dpi=300, bbox_inches='tight')
                messagebox.showinfo("Success", f"Plot saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save plot: {str(e)}")
    
    def export_data(self):
        """Export the current data"""
        if self.current_data is None:
            messagebox.showwarning("Warning", "No data to export!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", ".csv"), ("JSON files", ".json"), 
                      ("Excel files", ".xlsx"), ("All files", ".*")]
        )
        
        if file_path:
            try:
                if file_path.endswith('.csv'):
                    self.current_data.to_csv(file_path, index=False)
                elif file_path.endswith('.json'):
                    self.current_data.to_json(file_path, orient='records', indent=2)
                elif file_path.endswith('.xlsx'):
                    self.current_data.to_excel(file_path, index=False)
                
                messagebox.showinfo("Success", f"Data exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def clear_plot(self):
        """Clear the current plot"""
        for widget in self.plot_frame.winfo_children():
            widget.destroy()
        self.current_canvas = None
    
    def analyze_data(self):
        """Analyze the current data and show insights"""
        if self.current_data is None:
            messagebox.showwarning("Warning", "No data to analyze!")
            return
        
        self.analysis_text.delete(1.0, tk.END)
        
        analysis = f"""
🔍 CYBERSECURITY DATA ANALYSIS REPORT
{'='*50}

📊 DATASET OVERVIEW:
• Total Records: {len(self.current_data)}
• Columns: {len(self.current_data.columns)}
• Date Range: {self.get_date_range()}

🚨 SECURITY INSIGHTS:
{self.get_security_insights()}

📈 STATISTICAL SUMMARY:
{self.get_statistical_summary()}

🎯 RECOMMENDATIONS:
{self.get_recommendations()}

⚠ ALERTS:
{self.get_security_alerts()}
"""
        
        self.analysis_text.insert(1.0, analysis)
    
    def get_date_range(self):
        """Get the date range of the data"""
        if 'timestamp' in self.current_data.columns:
            try:
                min_date = self.current_data['timestamp'].min()
                max_date = self.current_data['timestamp'].max()
                return f"{min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"
            except:
                return "Unable to determine date range"
        return "No timestamp data available"
    
    def get_security_insights(self):
        """Generate security insights from the data"""
        insights = []
        
        if 'attack_type' in self.current_data.columns:
            top_attack = self.current_data['attack_type'].value_counts().index[0]
            insights.append(f"• Most common attack type: {top_attack}")
        
        if 'severity' in self.current_data.columns:
            critical_count = len(self.current_data[self.current_data['severity'] == 'Critical'])
            insights.append(f"• Critical incidents: {critical_count}")
        
        if 'action' in self.current_data.columns:
            blocked_rate = (self.current_data['action'] == 'BLOCK').mean() * 100
            insights.append(f"• Firewall block rate: {blocked_rate:.1f}%")
        
        if 'source_ip' in self.current_data.columns:
            unique_sources = self.current_data['source_ip'].nunique()
            insights.append(f"• Unique source IPs: {unique_sources}")
        
        return '\n'.join(insights) if insights else "No specific insights available"
    
    def get_statistical_summary(self):
        """Get statistical summary of the data"""
        numeric_cols = self.current_data.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 0:
            return str(self.current_data[numeric_cols].describe())
        return "No numeric data available for statistical summary"
    
    def get_recommendations(self):
        """Generate security recommendations"""
        recommendations = [
            "• Implement multi-factor authentication for all user accounts",
            "• Regular security awareness training for employees",
            "• Keep all systems and software updated with latest patches",
            "• Monitor network traffic for unusual patterns",
            "• Implement proper backup and disaster recovery procedures",
            "• Regular vulnerability assessments and penetration testing",
            "• Implement proper access controls and principle of least privilege"
        ]
        return '\n'.join(recommendations)
    
    def get_security_alerts(self):
        """Generate security alerts based on data analysis"""
        alerts = []
        
        if self.current_data is not None:
            if 'severity' in self.current_data.columns:
                critical_count = len(self.current_data[self.current_data['severity'] == 'Critical'])
                if critical_count > 5:
                    alerts.append(f"⚠ HIGH: {critical_count} critical incidents detected!")
            
            if 'timestamp' in self.current_data.columns:
                try:
                    recent_data = self.current_data[self.current_data['timestamp'] > 
                                                  (datetime.now() - timedelta(days=1))]
                    if len(recent_data) > 100:
                        alerts.append("⚠ MEDIUM: High activity in last 24 hours")
                except:
                    pass
        
        if not alerts:
            alerts.append("✅ No immediate security alerts")
        
        return '\n'.join(alerts)
    
    def generate_report(self):
        """Generate a comprehensive security report"""
        if self.current_data is None:
            messagebox.showwarning("Warning", "No data available for report!")
            return
        
        report_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", ".txt"), ("All files", ".*")]
        )
        
        if report_path:
            try:
                with open(report_path, 'w') as f:
                    f.write(self.analysis_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Report saved to {report_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = CyberSecurityPlotCreator(root)
    root.mainloop()

if __name__ == "__main__":
    main()