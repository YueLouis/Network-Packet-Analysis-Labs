"""
Lab 3.3: ML-Based Protocol Classification
==========================================

Sử dụng Machine Learning (Random Forest) để tự động nhận diện protocol
từ đặc điểm của packet (size, ports, payload characteristics).

Author: Network Programming Lab
Date: January 2026
"""

from scapy.all import *
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pickle
import os

class ProtocolClassifier:
    """ML-based protocol identification using Random Forest"""
    
    def __init__(self, n_estimators=100):
        """
        Initialize classifier
        
        Args:
            n_estimators: Number of trees in Random Forest (default: 100)
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1  # Use all CPU cores
        )
        self.trained = False
        self.protocol_labels = []
    
    def extract_features(self, packet):
        """
        Extract statistical features from packet
        
        Features extracted:
        1. Packet size
        2. Has TCP layer (0/1)
        3. Has UDP layer (0/1)
        4. Source port
        5. Destination port
        6. Payload length
        7. First payload byte
        8. Average payload byte value
        
        Args:
            packet: Scapy packet object
            
        Returns:
            numpy array of shape (1, 8)
        """
        features = []
        
        # Feature 1: Packet size
        features.append(len(packet))
        
        # Features 2-3: Protocol indicators
        features.append(1 if packet.haslayer(TCP) else 0)
        features.append(1 if packet.haslayer(UDP) else 0)
        
        # Features 4-5: Ports
        if packet.haslayer(TCP):
            features.extend([packet[TCP].sport, packet[TCP].dport])
        elif packet.haslayer(UDP):
            features.extend([packet[UDP].sport, packet[UDP].dport])
        else:
            features.extend([0, 0])
        
        # Features 6-8: Payload characteristics
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            features.append(len(payload))
            features.append(payload[0] if payload else 0)  # First byte
            features.append(sum(payload) / len(payload) if payload else 0)  # Average byte value
        else:
            features.extend([0, 0, 0])
        
        return np.array(features).reshape(1, -1)
    
    def train(self, packets, labels):
        """
        Train classifier on labeled packets
        
        Args:
            packets: List of Scapy packet objects
            labels: List of protocol labels (strings)
            
        Example:
            >>> http_pkts = rdpcap('http.pcap')
            >>> ssh_pkts = rdpcap('ssh.pcap')
            >>> all_pkts = http_pkts + ssh_pkts
            >>> labels = ['HTTP']*len(http_pkts) + ['SSH']*len(ssh_pkts)
            >>> classifier.train(all_pkts, labels)
        """
        print(f"[*] Extracting features from {len(packets)} packets...")
        X = np.vstack([self.extract_features(pkt) for pkt in packets])
        y = np.array(labels)
        
        # Store unique protocol labels
        self.protocol_labels = list(set(labels))
        
        print(f"[*] Training Random Forest with {len(self.protocol_labels)} classes...")
        print(f"    Classes: {', '.join(self.protocol_labels)}")
        
        self.model.fit(X, y)
        self.trained = True
        
        # Calculate training accuracy
        train_score = self.model.score(X, y)
        print(f"[✓] Training complete! Accuracy: {train_score:.2%}")
    
    def predict(self, packet):
        """
        Predict protocol for packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict with 'protocol' and 'confidence' keys
            
        Raises:
            ValueError: If model not trained
        """
        if not self.trained:
            raise ValueError("Model not trained! Call train() first.")
        
        features = self.extract_features(packet)
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0]
        
        return {
            'protocol': prediction,
            'confidence': max(probability),
            'probabilities': dict(zip(self.model.classes_, probability))
        }
    
    def predict_batch(self, packets):
        """
        Predict protocols for multiple packets (faster than predict() loop)
        
        Args:
            packets: List of Scapy packet objects
            
        Returns:
            List of prediction dicts
        """
        if not self.trained:
            raise ValueError("Model not trained! Call train() first.")
        
        X = np.vstack([self.extract_features(pkt) for pkt in packets])
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        results = []
        for pred, prob in zip(predictions, probabilities):
            results.append({
                'protocol': pred,
                'confidence': max(prob),
                'probabilities': dict(zip(self.model.classes_, prob))
            })
        
        return results
    
    def save_model(self, filepath):
        """Save trained model to disk"""
        if not self.trained:
            raise ValueError("Cannot save untrained model")
        
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'protocol_labels': self.protocol_labels
            }, f)
        print(f"[✓] Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model from disk"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.protocol_labels = data['protocol_labels']
            self.trained = True
        print(f"[✓] Model loaded from {filepath}")
    
    def evaluate(self, test_packets, test_labels):
        """
        Evaluate model on test set
        
        Args:
            test_packets: List of test packets
            test_labels: List of true labels
            
        Returns:
            dict with accuracy, per-class metrics
        """
        if not self.trained:
            raise ValueError("Model not trained!")
        
        X_test = np.vstack([self.extract_features(pkt) for pkt in test_packets])
        y_test = np.array(test_labels)
        
        accuracy = self.model.score(X_test, y_test)
        
        # Per-class accuracy
        predictions = self.model.predict(X_test)
        per_class = {}
        
        for protocol in self.protocol_labels:
            mask = y_test == protocol
            if mask.sum() > 0:
                class_acc = (predictions[mask] == protocol).sum() / mask.sum()
                per_class[protocol] = class_acc
        
        return {
            'accuracy': accuracy,
            'per_class_accuracy': per_class
        }


# =============================================================================
# Helper Functions
# =============================================================================

def create_synthetic_packets():
    """
    Create synthetic training packets for demonstration
    (In real scenario, use actual PCAP files)
    
    Returns:
        packets: List of packets
        labels: List of protocol labels
    """
    packets = []
    labels = []
    
    # HTTP packets
    for i in range(100):
        pkt = IP(dst="93.184.216.34")/TCP(sport=random.randint(50000, 60000), dport=80)/Raw(load=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        packets.append(pkt)
        labels.append('HTTP')
    
    # SSH packets
    for i in range(100):
        pkt = IP(dst="192.168.1.100")/TCP(sport=random.randint(50000, 60000), dport=22)/Raw(load=b'SSH-2.0-OpenSSH_8.2\r\n')
        packets.append(pkt)
        labels.append('SSH')
    
    # DNS packets
    for i in range(100):
        pkt = IP(dst="8.8.8.8")/UDP(sport=random.randint(50000, 60000), dport=53)/Raw(load=b'\x00\x01\x01\x00\x00\x01\x00\x00')
        packets.append(pkt)
        labels.append('DNS')
    
    return packets, labels


if __name__ == '__main__':
    print("=" * 60)
    print("Lab 3.3: ML-Based Protocol Classification")
    print("=" * 60)
    print()
    
    # Create classifier
    classifier = ProtocolClassifier(n_estimators=100)
    
    # Option 1: Train on synthetic data (for demo)
    print("[*] Creating synthetic training data...")
    packets, labels = create_synthetic_packets()
    
    # Option 2: Train on real PCAP files (uncomment if you have them)
    # http_packets = rdpcap('http.pcap')[:100]
    # ssh_packets = rdpcap('ssh.pcap')[:100]
    # dns_packets = rdpcap('dns.pcap')[:100]
    # packets = http_packets + ssh_packets + dns_packets
    # labels = ['HTTP']*100 + ['SSH']*100 + ['DNS']*100
    
    print(f"[*] Total training samples: {len(packets)}")
    print()
    
    # Train model
    classifier.train(packets, labels)
    print()
    
    # Test predictions
    print("[*] Testing predictions...")
    print()
    
    # Test 1: HTTP packet
    test_http = IP()/TCP(dport=80)/Raw(load=b'GET / HTTP/1.1\r\n')
    result = classifier.predict(test_http)
    print(f"Test 1 - HTTP packet:")
    print(f"  Predicted: {result['protocol']} (confidence: {result['confidence']:.2%})")
    print(f"  Probabilities: {result['probabilities']}")
    print()
    
    # Test 2: SSH packet
    test_ssh = IP()/TCP(dport=22)/Raw(load=b'SSH-2.0-OpenSSH\r\n')
    result = classifier.predict(test_ssh)
    print(f"Test 2 - SSH packet:")
    print(f"  Predicted: {result['protocol']} (confidence: {result['confidence']:.2%})")
    print(f"  Probabilities: {result['probabilities']}")
    print()
    
    # Test 3: DNS packet
    test_dns = IP()/UDP(dport=53)/Raw(load=b'\x00\x01\x01\x00')
    result = classifier.predict(test_dns)
    print(f"Test 3 - DNS packet:")
    print(f"  Predicted: {result['protocol']} (confidence: {result['confidence']:.2%})")
    print(f"  Probabilities: {result['probabilities']}")
    print()
    
    # Save model
    model_path = 'protocol_classifier.pkl'
    classifier.save_model(model_path)
    print()
    
    print("[✓] Demo complete!")
