from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import pickle
import pandas as pd
import numpy as np
from datetime import datetime
import os
import sys

import sys

from network_scanner.scanner import scan_ip
from packet_monitor.monitor import monitor_instance
from device_detector.detector import scan_network_devices

app = Flask(__name__)
app.secret_key = 'cyber_security_secret_key'

# Load ML Model
try:
    with open('model.pkl', 'rb') as f:
        model_data = pickle.load(f)
        clf = model_data['model']
        encoders = model_data['encoders']
        features = model_data['features']
except Exception as e:
    print(f"Error loading model: {e}")
    clf = None

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                        (username, password)).fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({'status': 'success', 'redirect': url_for('dashboard')})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials detected!'}), 401

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/scan', methods=['POST'])
def scan_packet():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    
    try:
        # Preprocess input
        input_df = pd.DataFrame([{
            'protocol_type': data['protocol'],
            'service': data['service'],
            'flag': data['flag'],
            'src_bytes': int(data['src_bytes']),
            'dst_bytes': int(data['dst_bytes']),
            'duration': int(data['duration'])
        }])
        
        # Encode
        for col in ['protocol_type', 'service', 'flag']:
            if col in encoders:
                try:
                    input_df[col] = encoders[col].transform(input_df[col])
                except:
                    # Fallback for unseen labels
                    input_df[col] = 0
        
        # Predict
        prediction = clf.predict(input_df)[0]
        result = "INTRUSION DETECTED" if prediction == 1 else "NORMAL TRAFFIC"
        status = "Warning" if prediction == 1 else "Safe"
        
        # Log entry
        conn = get_db_connection()
        conn.execute('INSERT INTO logs (source_ip, protocol, service, attack_type, status) VALUES (?, ?, ?, ?, ?)',
                    ('192.168.1.' + str(np.random.randint(2, 254)), data['protocol'], data['service'], 
                     'Malicious Packet' if prediction == 1 else 'None', status))
        
        if prediction == 1:
            # Randomly block some detected intrusions for the demo
            if np.random.random() > 0.5:
                ip = '192.168.1.' + str(np.random.randint(100, 200))
                try:
                    conn.execute('INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)', (ip, 'AI-IDS Detection'))
                except: pass
                
        conn.commit()
        conn.close()
        
        return jsonify({'result': result, 'prediction': int(prediction)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/live_scan', methods=['POST'])
def perform_live_scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    ip_to_scan = data.get('ip')
    
    if not ip_to_scan:
        return jsonify({'error': 'No IP provided'}), 400
        
    results = scan_ip(ip_to_scan)
    if "error" in results:
        return jsonify(results), 400
        
    return jsonify(results)

@app.route('/api/device_scan', methods=['POST'])
def perform_device_scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    ip_range = data.get('ip_range', '192.168.1.0/24')
    
    results = scan_network_devices(ip_range)
    return jsonify(results)

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    total = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    intrusions = conn.execute('SELECT COUNT(*) FROM logs WHERE status = "Warning"').fetchone()[0]
    normal = total - intrusions
    
    suspicious_ips = len(conn.execute('SELECT DISTINCT source_ip FROM logs WHERE status = "Warning"').fetchall())
    active_connections = len(monitor_instance.packets) if monitor_instance.is_monitoring else np.random.randint(15, 45)
    
    # Random simulation for empty state or to make it look "live"
    if total < 10:
        total += 1245 + (len(monitor_instance.packets) if monitor_instance.is_monitoring else 0)
        intrusions += 234
        suspicious_ips += 12
        normal = total - intrusions
        
    # Get active devices info (Mocked count for stats overview)
    active_devices_count = np.random.randint(8, 25)
        
    logs = [dict(row) for row in conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10').fetchall()]
    blocked = [dict(row) for row in conn.execute('SELECT * FROM blocked_ips ORDER BY timestamp DESC LIMIT 5').fetchall()]
    
    conn.close()
    
    return jsonify({
        'total': total,
        'intrusions': intrusions,
        'normal': normal,
        'suspicious_ips': suspicious_ips,
        'active_connections': active_connections,
        'active_devices': active_devices_count,
        'threat_level': 'High' if (intrusions/total if total > 0 else 0) > 0.2 else 'Low',
        'logs': logs,
        'blocked': blocked
    })

@app.route('/api/live_packets', methods=['GET'])
def get_live_packets():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    packets = monitor_instance.get_recent_packets(50)
    
    # Run through AI
    for pkt in packets:
        if clf is not None and not pkt.get('is_ai_checked'):
            try:
                service_map = {80: 'http', 21: 'ftp', 53: 'dns', 25: 'smtp', 22: 'ssh'}
                svc = service_map.get(pkt.get('service_port', 0), 'private')
                
                input_df = pd.DataFrame([{
                    'protocol_type': pkt['protocol'].lower(),
                    'service': svc,
                    'flag': 'SF',
                    'src_bytes': pkt['size'],
                    'dst_bytes': 0,
                    'duration': 0
                }])
                
                for col in ['protocol_type', 'service', 'flag']:
                    if col in encoders:
                        try:
                            input_df[col] = encoders[col].transform(input_df[col])
                        except:
                            input_df[col] = 0
                            
                prediction = clf.predict(input_df)[0]
                if prediction == 1:
                    pkt['is_suspicious'] = True
                    pkt['attack_type'] = "AI Detected Anomaly"
                    pkt['threat_level'] = "High"
                
                pkt['is_ai_checked'] = True
            except Exception as e:
                pass
                
    return jsonify(packets)

@app.route('/api/start_monitor', methods=['POST'])
def start_monitor():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    monitor_instance.start()
    return jsonify({'status': 'Monitoring started'})

@app.route('/api/stop_monitor', methods=['POST'])
def stop_monitor():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    monitor_instance.stop()
    return jsonify({'status': 'Monitoring stopped'})

@app.route('/api/logs')
def get_all_logs():
    conn = get_db_connection()
    logs = [dict(row) for row in conn.execute('SELECT * FROM logs ORDER BY timestamp DESC').fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/api/blocked')
def get_blocked_ips():
    conn = get_db_connection()
    ips = [dict(row) for row in conn.execute('SELECT * FROM blocked_ips ORDER BY timestamp DESC').fetchall()]
    conn.close()
    return jsonify(ips)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
