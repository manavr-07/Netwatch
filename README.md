# Netwatch

A network anomaly detection tool designed to identify and alert on suspicious network patterns and potential security threats in real-time.

## Overview

Netwatch is a comprehensive network monitoring and anomaly detection system that leverages machine learning and statistical analysis to identify abnormal network behavior. It provides real-time monitoring, alerting, and detailed reporting capabilities for network infrastructure.

## Key Features

- Real-time network traffic monitoring and analysis
- Automated anomaly detection using machine learning algorithms
- Customizable alert thresholds and notifications
- Historical data analysis and trend reporting
- Dashboard for visualizing network metrics and anomalies
- Support for multiple data sources and network interfaces
- Export functionality for compliance and auditing purposes
- RESTful API for integration with other systems

## Technology Stack

Netwatch is built with:

- **Python** (69.5%) - Core backend and machine learning components
- **JavaScript** (15.7%) - Frontend interface and real-time updates
- **CSS** (12.2%) - UI styling and responsive design
- **HTML** (2.6%) - Markup structure

## Requirements

- Python 3.8 or higher
- Node.js 14.0 or higher
- 4GB RAM minimum (8GB recommended)
- 2GB disk space for data storage
- Linux/macOS/Windows operating system

## Installation

### Prerequisites

Ensure you have Python and Node.js installed on your system:

```bash
python --version
node --version
```

### Backend Setup

1. Clone the repository:

```bash
git clone https://github.com/manavr-07/Netwatch.git
cd Netwatch
```

2. Create a Python virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

### Frontend Setup

1. Navigate to the frontend directory:

```bash
cd frontend
```

2. Install Node.js dependencies:

```bash
npm install
```

3. Build the frontend:

```bash
npm run build
```

## Configuration

Create a `config.json` file in the project root directory:

```json
{
  "server": {
    "host": "localhost",
    "port": 5000,
    "debug": false
  },
  "database": {
    "type": "sqlite",
    "path": "./data/netwatch.db"
  },
  "monitoring": {
    "interval": 60,
    "interfaces": ["eth0"],
    "packet_capture": true
  },
  "alerts": {
    "enabled": true,
    "threshold": 0.85,
    "notification_email": "admin@example.com"
  },
  "ml_model": {
    "algorithm": "isolation_forest",
    "sensitivity": "medium"
  }
}
```

## Usage

### Starting the Application

1. Start the backend server:

```bash
python app.py
```

The API will be available at `http://localhost:5000`

2. In a new terminal, start the frontend:

```bash
cd frontend
npm start
```

The dashboard will be available at `http://localhost:3000`

### Monitoring Network Traffic

Access the web dashboard to:

- View real-time network statistics
- Monitor active connections and data flow
- Review detected anomalies
- Configure alert settings
- Analyze historical trends

## API Endpoints

### Network Metrics

- `GET /api/metrics/current` - Get current network metrics
- `GET /api/metrics/historical` - Get historical metrics with optional date range
- `POST /api/metrics/export` - Export metrics to CSV or JSON

### Anomalies

- `GET /api/anomalies` - List detected anomalies
- `GET /api/anomalies/:id` - Get details of a specific anomaly
- `POST /api/anomalies/acknowledge` - Mark anomaly as acknowledged

### Configuration

- `GET /api/config` - Get current configuration
- `PUT /api/config` - Update configuration settings
- `GET /api/config/validate` - Validate configuration

### System

- `GET /api/health` - Check system health status
- `GET /api/logs` - Retrieve system logs
- `POST /api/restart` - Restart monitoring service

## Architecture

### Components

**Backend Service**
- Traffic capture and packet analysis
- Statistical analysis and baseline computation
- Machine learning model for anomaly detection
- Data storage and retrieval
- API server for client communication

**Frontend Dashboard**
- Real-time metric visualization
- Anomaly alert display
- Configuration management interface
- Historical data analysis and reporting

**Database**
- Stores network metrics and anomalies
- Maintains configuration and user settings
- Logs monitoring events and alerts

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/anomaly-detection-improvement`)
3. Make your changes with clear, descriptive commits
4. Write or update tests for new functionality
5. Ensure all tests pass (`npm test` and `python -m pytest`)
6. Submit a pull request with a detailed description of your changes

## Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.

For documentation and guides, visit the project wiki and documentation files.

## Author

Manav Raitani

## License

MIT License - see LICENSE file for details

## Disclaimer

Netwatch is provided as-is for network monitoring and anomaly detection purposes. Users are responsible for complying with local laws and regulations regarding network monitoring and traffic analysis.
