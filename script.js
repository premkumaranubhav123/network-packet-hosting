class PacketAnalyzer {
    constructor() {
        this.packetData = [];
        this.simulationRunning = true;
        this.protocolNames = {1: 'ICMP', 6: 'TCP', 17: 'UDP'};
        this.updateInterval = null;
        
        this.sourceIps = [
            ...Array.from({length: 49}, (_, i) => `192.168.1.${i + 1}`),
            ...Array.from({length: 19}, (_, i) => `10.0.0.${i + 1}`)
        ];
        
        this.destIps = [
            '8.8.8.8', '8.8.4.4', '1.1.1.1',
            '142.251.42.206', '151.101.1.69',
            '13.107.42.14', '204.79.197.203',
            '185.199.108.153', '140.82.121.3',
            '52.114.128.66', '13.107.246.40'
        ];
        
        this.packetSizes = [64, 128, 256, 512, 1024, 1500];
        this.ports = [80, 443, 53, 22, 25, 110, 993, 995, 143, 21, 8080, 8443];
        
        this.initializeEventListeners();
        this.startSimulation();
    }

    initializeEventListeners() {
        document.getElementById('stop-simulation').addEventListener('click', () => this.stopSimulation());
        document.getElementById('reset-simulation').addEventListener('click', () => this.resetSimulation());
        document.getElementById('apply-filters-btn').addEventListener('click', () => this.updateDashboard());
    }

    generatePacketBatch(count = 5) {
        const packets = [];
        const currentTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
        
        for (let i = 0; i < count; i++) {
            let protocol, destPort, size;
            
            if (Math.random() < 0.3) {
                protocol = 6;
                destPort = [80, 443, 8080, 8443][Math.floor(Math.random() * 4)];
                size = [512, 1024, 1500][Math.floor(Math.random() * 3)];
            } else if (Math.random() < 0.5) {
                protocol = 17;
                destPort = 53;
                size = [64, 128, 256][Math.floor(Math.random() * 3)];
            } else {
                protocol = [1, 6, 17][Math.floor(Math.random() * 3)];
                destPort = this.ports[Math.floor(Math.random() * this.ports.length)];
                size = this.packetSizes[Math.floor(Math.random() * this.packetSizes.length)];
            }
            
            const isAnomalous = Math.random() < 0.05;
            if (isAnomalous) {
                size = [5000, 8000, 10000][Math.floor(Math.random() * 3)];
                protocol = [1, 6, 17][Math.floor(Math.random() * 3)];
            }
            
            const packet = {
                timestamp: currentTime,
                source_ip: this.sourceIps[Math.floor(Math.random() * this.sourceIps.length)],
                destination_ip: this.destIps[Math.floor(Math.random() * this.destIps.length)],
                protocol: protocol,
                protocol_name: this.protocolNames[protocol] || 'Unknown',
                packet_size: size,
                source_port: Math.floor(Math.random() * (65535 - 10000 + 1)) + 10000,
                destination_port: destPort,
                is_anomalous: isAnomalous
            };
            packets.push(packet);
        }
        
        return packets;
    }

    startSimulation() {
        this.updateInterval = setInterval(() => {
            if (this.simulationRunning) {
                const newPackets = this.generatePacketBatch(Math.floor(Math.random() * 6) + 3);
                this.packetData.push(...newPackets);
                
                // Keep only last 1000 packets
                if (this.packetData.length > 1000) {
                    this.packetData = this.packetData.slice(-1000);
                }
                
                this.updateDashboard();
            }
        }, 2000);
    }

    stopSimulation() {
        this.simulationRunning = false;
        document.getElementById('simulation-status').textContent = 'Status: 🔴 Stopped';
        document.getElementById('simulation-status').style.color = '#dc3545';
    }

    resetSimulation() {
        this.packetData = [];
        this.simulationRunning = true;
        document.getElementById('simulation-status').textContent = 'Status: 🟢 Auto-Running';
        document.getElementById('simulation-status').style.color = '#28a745';
        this.updateDashboard();
    }

    calculateStatistics(filteredData) {
        if (filteredData.length === 0) {
            return {
                trafficVolume: 0,
                averageSize: 0,
                abnormalCount: 0,
                protocolCounts: {},
                anomalyCount: 0
            };
        }

        const trafficVolume = filteredData.length;
        const averageSize = filteredData.reduce((sum, p) => sum + p.packet_size, 0) / trafficVolume;
        
        const mean = averageSize;
        const std = Math.sqrt(
            filteredData.reduce((sum, p) => sum + Math.pow(p.packet_size - mean, 2), 0) / trafficVolume
        );
        
        const abnormalCount = std > 0 ? 
            filteredData.filter(p => Math.abs((p.packet_size - mean) / std) > 3).length : 0;

        const protocolCounts = {};
        filteredData.forEach(packet => {
            protocolCounts[packet.protocol_name] = (protocolCounts[packet.protocol_name] || 0) + 1;
        });

        // Anomaly count
        const anomalyCount = filteredData.filter(p => p.is_anomalous).length;

        return {
            trafficVolume,
            averageSize,
            abnormalCount,
            protocolCounts,
            anomalyCount
        };
    }

    updateDashboard() {
        try {
            let filteredData = [...this.packetData];
            
            // Apply filters
            const sourceIp = document.getElementById('source-ip-input').value;
            const destinationIp = document.getElementById('destination-ip-input').value;
            const protocol = document.getElementById('protocol-dropdown').value;
            
            if (sourceIp) {
                filteredData = filteredData.filter(p => p.source_ip === sourceIp);
            }
            if (destinationIp) {
                filteredData = filteredData.filter(p => p.destination_ip === destinationIp);
            }
            if (protocol && protocol !== 'all') {
                filteredData = filteredData.filter(p => p.protocol === parseInt(protocol));
            }
            
            const stats = this.calculateStatistics(filteredData);
            
            // Update statistics display
            document.getElementById('traffic-volume').textContent = 
                `📊 Traffic Volume: ${stats.trafficVolume} packets`;
            document.getElementById('average-packet-size').textContent = 
                `📦 Average Packet Size: ${stats.averageSize.toFixed(2)} bytes`;
            document.getElementById('abnormal-packets').textContent = 
                `⚠️ Abnormal Packets (Z-score > 3): ${stats.abnormalCount}`;
            
            const protocolStr = Object.entries(stats.protocolCounts)
                .map(([proto, count]) => `${proto}: ${count}`)
                .join(' | ');
            document.getElementById('protocol-counts').textContent = 
                `🔧 Protocols: ${protocolStr || 'None'}`;
            
            document.getElementById('anomaly-packet-count').textContent = 
                `🚨 Anomalous Packets: ${stats.anomalyCount}`;
            
            // Update chart
            this.updateChart(filteredData);
            
        } catch (error) {
            console.error('Error updating dashboard:', error);
        }
    }

    updateChart(data) {
        const timeIndices = data.map((_, index) => index);
        const packetSizes = data.map(p => p.packet_size);
        const protocols = data.map(p => p.protocol_name);
        const sourceIps = data.map(p => p.source_ip);
        const destIps = data.map(p => p.destination_ip);

        const trace = {
            x: timeIndices,
            y: packetSizes,
            mode: 'markers',
            type: 'scatter',
            marker: {
                size: 8,
                color: protocols.map(p => 
                    p === 'TCP' ? '#1f77b4' : 
                    p === 'UDP' ? '#ff7f0e' : 
                    '#2ca02c'
                )
            },
            text: protocols.map((p, i) => 
                `Protocol: ${p}<br>Source: ${sourceIps[i]}<br>Destination: ${destIps[i]}<br>Size: ${packetSizes[i]} bytes`
            ),
            hoverinfo: 'text'
        };

        const layout = {
            title: {
                text: `Packet Size Distribution (Total: ${data.length} packets)`,
                font: { size: 16 }
            },
            xaxis: {
                title: 'Packet Sequence',
                gridcolor: '#f0f0f0'
            },
            yaxis: {
                title: 'Packet Size (bytes)',
                gridcolor: '#f0f0f0'
            },
            plot_bgcolor: 'white',
            paper_bgcolor: 'white',
            showlegend: true,
            legend: {
                orientation: 'h',
                y: -0.2
            }
        };

        Plotly.react('live-update-plot', [trace], layout, {responsive: true});
    }
}

document.addEventListener('DOMContentLoaded', function() {
    new PacketAnalyzer();
});