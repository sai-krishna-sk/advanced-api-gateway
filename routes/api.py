from flask import Blueprint, request, jsonify
from services import elasticsearch_service, siem_integration
from utils import api_fuzzer
import datetime

api_bp = Blueprint('api', __name__)

@api_bp.route('/echo', methods=['POST'])
def echo():
    try:
        data = request.get_json()
        if data is None:
            raise ValueError("No JSON payload provided")
            
        log_entry = {
            "endpoint": "/api/echo",
            "data": data,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        
        # Attempt to index the log in Elasticsearch
        try:
            elasticsearch_service.index_log(log_entry)
        except Exception as e:
            print("Error indexing log in Elasticsearch:", e)
        
        # Attempt to send the log to SIEM
        try:
            siem_integration.send_to_siem(log_entry)
        except Exception as e:
            print("Error sending log to SIEM:", e)
        
        return jsonify({"message": "Echo", "data": data})
    except Exception as e:
        print("Error in echo endpoint:", e)
        return jsonify({"error": "Internal Server Error"}), 500

@api_bp.route('/fuzz', methods=['POST'])
def fuzz():
    try:
        grammar = request.get_json().get("grammar", {"sampleField": "string", "count": "number"})
        api_fuzzer.fuzz('/api/echo', grammar)
        return jsonify({"message": "Fuzzing initiated"})
    except Exception as e:
        print("Error during API fuzzing:", e)
        return jsonify({"message": "Error during fuzzing"}), 500

