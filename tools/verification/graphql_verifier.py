"""
GraphQL Verifier
================

Tests GraphQL endpoints for introspection and exposed schemas.
"""

import requests
import json
from typing import Optional, Dict, Any
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class GraphQLVerifier(BaseVerifier):
    """Verifies GraphQL endpoint exposure and introspection"""
    
    # Standard GraphQL introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                description
            }
        }
    }
    """
    
    # Simplified introspection for quick check
    SIMPLE_INTROSPECTION = """
    {
        __schema {
            types {
                name
            }
        }
    }
    """
    
    def verify(self, url: str) -> VerificationResult:
        """
        Test GraphQL endpoint for introspection
        
        Args:
            url: GraphQL endpoint URL
        
        Returns:
            VerificationResult with introspection details
        """
        if not url.startswith('http'):
            url = f"https://{url}"
        
        try:
            # Try simple introspection first
            response = requests.post(
                url,
                json={"query": self.SIMPLE_INTROSPECTION},
                headers=self.get_headers({"Content-Type": "application/json"}),
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Check if introspection succeeded
                    if "data" in data and "__schema" in data["data"]:
                        schema_data = data["data"]["__schema"]
                        types = schema_data.get("types", [])
                        type_names = [t.get("name") for t in types if t.get("name")]
                        
                        # Get full introspection
                        full_result = self._get_full_introspection(url)
                        
                        queries = []
                        mutations = []
                        
                        if full_result and "data" in full_result:
                            schema = full_result["data"].get("__schema", {})
                            query_type = schema.get("queryType", {}).get("name")
                            mutation_type = schema.get("mutationType", {}).get("name")
                            
                            # Extract available queries and mutations
                            for t in schema.get("types", []):
                                if t.get("name") == query_type:
                                    queries = [f.get("name") for f in t.get("fields", []) if f.get("name")]
                                elif t.get("name") == mutation_type:
                                    mutations = [f.get("name") for f in t.get("fields", []) if f.get("name")]
                        
                        return VerificationResult(
                            verified=True,
                            confidence=ConfidenceLevel.CONFIRMED,
                            severity=Severity.MEDIUM,
                            finding_type="graphql_introspection_enabled",
                            target=url,
                            details=f"GraphQL introspection is enabled! Schema with {len(type_names)} types exposed.",
                            proof={
                                "introspection_enabled": True,
                                "types_count": len(type_names),
                                "types": type_names[:20],  # First 20 types
                                "queries": queries[:10],  # First 10 queries
                                "mutations": mutations[:10],  # First 10 mutations
                                "full_schema_available": full_result is not None,
                            },
                            remediation="Disable introspection in production or require authentication for introspection queries",
                            cvss_score=5.3
                        )
                    
                    elif "errors" in data:
                        # GraphQL endpoint exists but introspection might be disabled
                        error_msg = data["errors"][0].get("message", "") if data["errors"] else ""
                        
                        if "introspection" in error_msg.lower():
                            return VerificationResult(
                                verified=True,
                                confidence=ConfidenceLevel.CONFIRMED,
                                severity=Severity.LOW,
                                finding_type="graphql_introspection_disabled",
                                target=url,
                                details="GraphQL endpoint exists but introspection is disabled (secure configuration)",
                                proof={"error": error_msg}
                            )
                        else:
                            return VerificationResult(
                                verified=True,
                                confidence=ConfidenceLevel.HIGH,
                                severity=Severity.LOW,
                                finding_type="graphql_endpoint",
                                target=url,
                                details=f"GraphQL endpoint exists. Error: {error_msg}",
                                proof={"errors": data["errors"]}
                            )
                
                except json.JSONDecodeError:
                    return VerificationResult(
                        verified=False,
                        confidence=ConfidenceLevel.MEDIUM,
                        severity=Severity.INFO,
                        finding_type="invalid_response",
                        target=url,
                        details="Endpoint returned non-JSON response",
                        proof={"response": response.text[:200]}
                    )
            
            elif response.status_code == 401:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.LOW,
                    finding_type="graphql_requires_auth",
                    target=url,
                    details="GraphQL endpoint exists but requires authentication",
                    proof={"status_code": 401}
                )
            
            elif response.status_code == 404:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.INFO,
                    finding_type="no_graphql",
                    target=url,
                    details="GraphQL endpoint not found (false positive)",
                    proof={}
                )
            
            else:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=Severity.INFO,
                    finding_type="unknown_status",
                    target=url,
                    details=f"Unexpected status code: {response.status_code}",
                    proof={"status_code": response.status_code}
                )
        
        except requests.exceptions.Timeout:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="timeout",
                target=url,
                details="Request timed out",
                proof={}
            )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="verification_error",
                target=url,
                details=f"Error: {str(e)}",
                proof={}
            )
    
    def _get_full_introspection(self, url: str) -> Optional[Dict]:
        """Get full introspection schema"""
        try:
            response = requests.post(
                url,
                json={"query": self.INTROSPECTION_QUERY},
                headers=self.get_headers({"Content-Type": "application/json"}),
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                return response.json()
        
        except:
            pass
        
        return None
    
    def check_console(self, base_url: str) -> VerificationResult:
        """Check for GraphQL playground/console exposure"""
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        
        console_paths = [
            "/graphql/console",
            "/graphql/playground",
            "/graphiql",
            "/graphql-playground",
        ]
        
        for path in console_paths:
            try:
                url = f"{base_url}{path}"
                response = requests.get(
                    url,
                    headers=self.get_headers(),
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code == 200 and len(response.content) > 0:
                    # Check for GraphQL console indicators
                    content_lower = response.text.lower()
                    if any(keyword in content_lower for keyword in ["graphql", "playground", "graphiql"]):
                        return VerificationResult(
                            verified=True,
                            confidence=ConfidenceLevel.CONFIRMED,
                            severity=Severity.MEDIUM,
                            finding_type="graphql_console_exposed",
                            target=url,
                            details=f"GraphQL console/playground exposed at {path}",
                            proof={
                                "url": url,
                                "path": path,
                                "content_length": len(response.content),
                            },
                            remediation="Disable GraphQL playground in production",
                            cvss_score=5.3
                        )
            
            except:
                continue
        
        return VerificationResult(
            verified=False,
            confidence=ConfidenceLevel.HIGH,
            severity=Severity.INFO,
            finding_type="no_console",
            target=base_url,
            details="No GraphQL console found",
            proof={}
        )
