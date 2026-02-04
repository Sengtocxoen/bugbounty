#!/usr/bin/env python3
"""
GraphQL Introspection Module
Detects GraphQL endpoints and performs schema introspection to map hidden queries/mutations.
Identifies exposed sensitive fields and potential security issues.
"""

import requests
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime


@dataclass
class GraphQLField:
    """A field in GraphQL schema"""
    name: str
    type: str
    description: str = ""
    is_deprecated: bool = False
    args: List[Dict] = field(default_factory=list)


@dataclass
class GraphQLType:
    """A type in GraphQL schema"""
    name: str
    kind: str  # OBJECT, INTERFACE, ENUM, etc.
    description: str = ""
    fields: List[GraphQLField] = field(default_factory=list)
    is_sensitive: bool = False


@dataclass
class GraphQLSchema:
    """Complete GraphQL schema"""
    endpoint: str
    queries: List[GraphQLField] = field(default_factory=list)
    mutations: List[GraphQLField] = field(default_factory=list)
    subscriptions: List[GraphQLField] = field(default_factory=list)
    types: List[GraphQLType] = field(default_factory=list)
    introspection_enabled: bool = False
    security_issues: List[str] = field(default_factory=list)


class GraphQLIntrospector:
    """Perform GraphQL introspection and analysis"""
    
    # Standard introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    
    def __init__(self, rate_limit: float = 2.0, user_agent: str = "BugBountyResearcher"):
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.user_agent = user_agent
        
        self.session = requests.Session()
        self.session.headers['User-Agent'] = user_agent
        self.session.headers['Content-Type'] = 'application/json'
    
    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()
    
    def detect_graphql(self, url: str) -> bool:
        """Detect if URL is a GraphQL endpoint"""
        self._rate_limit_wait()
        
        # Try common GraphQL paths
        paths = ['', '/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/query']
        
        for path in paths:
            test_url = url.rstrip('/') + path
            
            try:
                # Try a simple query
                payload = {
                    "query": "{ __typename }"
                }
                
                response = self.session.post(test_url, json=payload, timeout=10)
                
                # Check if response looks like GraphQL
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data or 'errors' in data:
                            return True
                    except:
                        pass
                        
            except:
                continue
        
        return False
    
    def introspect(self, endpoint: str, headers: Optional[Dict] = None) -> Optional[GraphQLSchema]:
        """
        Perform GraphQL introspection
        
        Args:
            endpoint: GraphQL endpoint URL
            headers: Optional custom headers (auth, etc.)
        """
        print(f"\n[*] GraphQL Introspection: {endpoint}")
        print("=" * 60)
        
        self._rate_limit_wait()
        
        # Prepare headers
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)
        
        # Send introspection query
        payload = {
            "query": self.INTROSPECTION_QUERY
        }
        
        try:
            response = self.session.post(endpoint, json=payload, headers=req_headers, timeout=15)
            
            if response.status_code != 200:
                print(f"  [!] Failed: HTTP {response.status_code}")
                return None
            
            data = response.json()
            
            # Check for errors
            if 'errors' in data:
                errors = data['errors']
                print(f"  [!] GraphQL Errors:")
                for error in errors:
                    print(f"      {error.get('message', 'Unknown error')}")
                
                # Check if introspection is disabled
                if any('introspection' in str(e).lower() for e in errors):
                    print("  [!] Introspection is DISABLED (good security practice)")
                    return None
                
                return None
            
            if 'data' not in data or '__schema' not in data['data']:
                print("  [!] Invalid introspection response")
                return None
            
            # Parse schema
            schema_data = data['data']['__schema']
            schema = self._parse_schema(endpoint, schema_data)
            
            print(f"\n  [SUCCESS] Introspection enabled!")
            print(f"    Queries: {len(schema.queries)}")
            print(f"    Mutations: {len(schema.mutations)}")
            print(f"    Subscriptions: {len(schema.subscriptions)}")
            print(f"    Types: {len(schema.types)}")
            
            return schema
            
        except requests.Timeout:
            print("  [!] Request timeout")
        except Exception as e:
            print(f"  [!] Error: {e}")
        
        return None
    
    def _parse_schema(self, endpoint: str, schema_data: Dict) -> GraphQLSchema:
        """Parse introspection response into schema object"""
        schema = GraphQLSchema(endpoint=endpoint, introspection_enabled=True)
        
        # Get type names
        query_type_name = schema_data.get('queryType', {}).get('name', 'Query')
        mutation_type_name = schema_data.get('mutationType', {}).get('name', 'Mutation') if schema_data.get('mutationType') else None
        subscription_type_name = schema_data.get('subscriptionType', {}).get('name', 'Subscription') if schema_data.get('subscriptionType') else None
        
        # Parse all types
        for type_data in schema_data.get('types', []):
            type_name = type_data.get('name', '')
            
            # Skip internal types
            if type_name.startswith('__'):
                continue
            
            gql_type = GraphQLType(
                name=type_name,
                kind=type_data.get('kind', ''),
                description=type_data.get('description', '')
            )
            
            # Check if type contains sensitive keywords
            sensitive_keywords = ['password', 'secret', 'token', 'key', 'credential', 'auth', 'private']
            if any(kw in type_name.lower() for kw in sensitive_keywords):
                gql_type.is_sensitive = True
                schema.security_issues.append(f"Type '{type_name}' may contain sensitive data")
            
            # Parse fields
            for field_data in type_data.get('fields', []) or []:
                field = GraphQLField(
                    name=field_data.get('name', ''),
                    type=self._get_type_string(field_data.get('type', {})),
                    description=field_data.get('description', ''),
                    is_deprecated=field_data.get('isDeprecated', False),
                    args=[
                        {
                            'name': arg.get('name', ''),
                            'type': self._get_type_string(arg.get('type', {}))
                        }
                        for arg in field_data.get('args', [])
                    ]
                )
                
                gql_type.fields.append(field)
                
                # Categorize field
                if type_name == query_type_name:
                    schema.queries.append(field)
                elif type_name == mutation_type_name:
                    schema.mutations.append(field)
                elif type_name == subscription_type_name:
                    schema.subscriptions.append(field)
            
            schema.types.append(gql_type)
        
        # Analyze security
        self._analyze_security(schema)
        
        return schema
    
    def _get_type_string(self, type_data: Dict) -> str:
        """Convert type data to string representation"""
        if not type_data:
            return "Unknown"
        
        kind = type_data.get('kind', '')
        name = type_data.get('name', '')
        of_type = type_data.get('ofType')
        
        if kind == 'NON_NULL':
            return self._get_type_string(of_type) + '!'
        elif kind == 'LIST':
            return '[' + self._get_type_string(of_type) + ']'
        else:
            return name or 'Unknown'
    
    def _analyze_security(self, schema: GraphQLSchema):
        """Analyze schema for security issues"""
        # Check for exposed sensitive queries
        sensitive_queries = [q for q in schema.queries if any(
            kw in q.name.lower() for kw in ['user', 'admin', 'secret', 'token', 'password', 'credit']
        )]
        
        if sensitive_queries:
            schema.security_issues.append(f"Found {len(sensitive_queries)} potentially sensitive queries")
        
        # Check for dangerous mutations
        dangerous_mutations = [m for m in schema.mutations if any(
            kw in m.name.lower() for kw in ['delete', 'admin', 'privilege', 'role', 'permission']
        )]
        
        if dangerous_mutations:
            schema.security_issues.append(f"Found {len(dangerous_mutations)} potentially dangerous mutations")
        
        # Check for debug/internal fields
        debug_fields = []
        for gql_type in schema.types:
            for field in gql_type.fields:
                if any(kw in field.name.lower() for kw in ['debug', 'internal', 'test', '__']):
                    debug_fields.append(f"{gql_type.name}.{field.name}")
        
        if debug_fields:
            schema.security_issues.append(f"Found {len(debug_fields)} debug/internal fields")


def save_schema(schema: GraphQLSchema, output_file: str):
    """Save GraphQL schema to JSON"""
    data = {
        'endpoint': schema.endpoint,
        'introspection_enabled': schema.introspection_enabled,
        'queries': [
            {
                'name': q.name,
                'type': q.type,
                'description': q.description,
                'args': q.args
            }
            for q in schema.queries
        ],
        'mutations': [
            {
                'name': m.name,
                'type': m.type,
                'description': m.description,
                'args': m.args
            }
            for m in schema.mutations
        ],
        'subscriptions': [
            {
                'name': s.name,
                'type': s.type,
                'description': s.description
            }
            for s in schema.subscriptions
        ],
        'types': [
            {
                'name': t.name,
                'kind': t.kind,
                'description': t.description,
                'fields_count': len(t.fields),
                'is_sensitive': t.is_sensitive
            }
            for t in schema.types
        ],
        'security_issues': schema.security_issues
    }
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n[*] Schema saved to: {output_file}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="GraphQL Introspection Tool")
    parser.add_argument("endpoint", help="GraphQL endpoint URL")
    parser.add_argument("--header", "-H", action='append', help="Custom header (format: 'Name: Value')")
    parser.add_argument("--output", "-o", help="Output JSON file")
    
    args = parser.parse_args()
    
    # Parse custom headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()
    
    introspector = GraphQLIntrospector()
    schema = introspector.introspect(args.endpoint, headers=headers)
    
    if schema:
        print("\n" + "="*60)
        print("GRAPHQL SCHEMA SUMMARY")
        print("="*60)
        
        if schema.queries:
            print(f"\nQueries ({len(schema.queries)}):")
            for q in schema.queries[:10]:
                print(f"  - {q.name}: {q.type}")
            if len(schema.queries) > 10:
                print(f"  ... and {len(schema.queries) - 10} more")
        
        if schema.mutations:
            print(f"\nMutations ({len(schema.mutations)}):")
            for m in schema.mutations[:10]:
                print(f"  - {m.name}: {m.type}")
            if len(schema.mutations) > 10:
                print(f"  ... and {len(schema.mutations) - 10} more")
        
        if schema.security_issues:
            print(f"\n[!] SECURITY ISSUES:")
            for issue in schema.security_issues:
                print(f"  - {issue}")
        
        if args.output:
            save_schema(schema, args.output)
    else:
        print("\n[!] Introspection failed or is disabled")
