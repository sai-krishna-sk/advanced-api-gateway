from faker import Faker
import requests
import os
import rstr

fake = Faker()

def fuzz(api_endpoint, grammar):
    random_data = {}
    for key, rule in grammar.items():
        if rule.startswith("regex:"):
            # Grammar rule format: "regex:<pattern>"
            pattern = rule.split("regex:", 1)[1]
            random_data[key] = rstr.xeger(pattern)
        elif rule == "string":
            random_data[key] = fake.text(max_nb_chars=20)
        elif rule == "number":
            random_data[key] = fake.random_int()
        elif rule == "boolean":
            random_data[key] = fake.boolean()
        else:
            random_data[key] = fake.word()
    print(f"Fuzzing API {api_endpoint} with data: {random_data}")
    try:
        port = os.getenv("PORT", 8443)
        url = f"https://localhost:{port}{api_endpoint}"
        # For testing with self-signed certificates, disable verification (do not use in production)
        response = requests.post(url, json=random_data, verify=False)
        print("Fuzzing response:", response.json())
    except Exception as e:
        print("Error during fuzzing:", e)

