import gradio as gr
import pandas as pd
from threat_detector import ThreatDetector
import plotly.graph_objects as go
import time

# Initialize threat detector
detector = ThreatDetector()

def analyze_threat(url_input, traffic_data=None):
    """Analyze threat for given input"""
    
    # Show loading animation
    yield "🔍 Analyzing threat...", "", "", ""
    
    # Analyze URL
    url_result = detector.analyze_url(url_input)
    
    # Create threat level visualization
    threat_levels = ["Low", "Medium", "High", "Critical"]
    threat_values = [0.2, 0.4, 0.6, 0.8]
    current_level_index = threat_levels.index(url_result["threat_level"])
    current_value = threat_values[current_level_index]
    
    # Create gauge chart
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = current_value,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"Threat Level: {url_result['threat_level']}"},
        delta = {'reference': 0.3},
        gauge = {
            'axis': {'range': [0, 1]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 0.3], 'color': "lightgreen"},
                {'range': [0.3, 0.6], 'color': "yellow"},
                {'range': [0.6, 0.8], 'color': "orange"},
                {'range': [0.8, 1], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 0.9
            }
        }
    ))
    
    fig.update_layout(height=300)
    
    # Prepare results
    threats_list = "\n".join([f"• {threat}" for threat in url_result["threats_detected"]]) or "No specific threats detected"
    
    # Create results table
    results_df = pd.DataFrame({
        "Metric": ["Threat Level", "Confidence Score", "Threats Detected", "Recommendation"],
        "Value": [
            url_result["threat_level"],
            f"{url_result['confidence']:.2%}",
            len(url_result["threats_detected"]),
            url_result["recommendation"]
        ]
    })
    
    return url_result["threat_level"], threats_list, url_result["recommendation"], fig, results_df

def create_demo_data():
    """Create sample data for demonstration"""
    sample_data = {
        "Safe URL": "https://www.google.com",
        "Suspicious URL": "https://secure-login-verify-account.com",
        "High Risk URL": "http://185.123.45.67/update-password.exe"
    }
    return sample_data

# Create Gradio interface
with gr.Blocks(theme=gr.themes.Soft(), title="AI Threat Detection System") as demo:
    gr.Markdown("""
    # 🛡️ AI-Based Threat Detection & Prevention System
    ### Detect and prevent cybersecurity threats using machine learning
    """)
    
    with gr.Row():
        with gr.Column():
            url_input = gr.Textbox(
                label="Enter URL to Analyze",
                placeholder="https://example.com",
                info="Enter any URL to check for potential threats"
            )
            
            analyze_btn = gr.Button("🚀 Analyze Threat", variant="primary")
            
            with gr.Accordion("Sample URLs for Testing"):
                gr.Markdown("""
                **Safe Examples:**
                - https://www.google.com
                - https://github.com
                - https://www.microsoft.com
                
                **Suspicious Examples:**
                - https://secure-login-verify.com
                - http://update-account-info.net
                - https://password-reset-urgent.com
                """)
        
        with gr.Column():
            threat_level = gr.Textbox(label="Threat Level", interactive=False)
            threats_detected = gr.Textbox(label="Threats Detected", lines=3, interactive=False)
            recommendation = gr.Textbox(label="Recommendation", lines=2, interactive=False)
            plot_output = gr.Plot(label="Threat Level Visualization")
    
    with gr.Row():
        results_table = gr.Dataframe(
            headers=["Metric", "Value"],
            datatype=["str", "str"],
            interactive=False,
            label="Analysis Results"
        )
    
    # Additional features
    with gr.Accordion("🛠️ Advanced Threat Analysis"):
        with gr.Row():
            file_upload = gr.File(label="Upload File for Analysis")
            network_traffic = gr.Textbox(
                label="Network Traffic Data (JSON)",
                placeholder='{"connections": [], "bandwidth": 0}',
                lines=3
            )
        
        advanced_analyze_btn = gr.Button("🔍 Advanced Analysis", variant="secondary")
    
    # Statistics section
    with gr.Accordion("📊 System Statistics", open=False):
        with gr.Row():
            total_scans = gr.Number(label="Total Scans", value=0)
            threats_blocked = gr.Number(label="Threats Blocked", value=0)
            detection_rate = gr.Number(label="Detection Rate", value=0)
        
        update_stats_btn = gr.Button("🔄 Update Statistics")
    
    # Event handlers
    analyze_btn.click(
        fn=analyze_threat,
        inputs=[url_input],
        outputs=[threat_level, threats_detected, recommendation, plot_output, results_table]
    )
    
    def update_statistics():
        return 150, 23, 85.4
    
    update_stats_btn.click(
        fn=update_statistics,
        outputs=[total_scans, threats_blocked, detection_rate]
    )

if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False
    )
