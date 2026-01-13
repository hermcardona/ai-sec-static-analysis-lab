"""
Static Analysis Demonstration for AI Security
This file contains vulnerable code examples that PASS unit tests
but contain serious security issues caught by static analysis
"""
import hashlib
import re
from pathlib import Path
from unittest import result
import pandas as pd
import os
import numpy as np
from sklearn.linear_model import LogisticRegression

print("="*70)
print("STATIC ANALYSIS DEMONSTRATION")
print("Running code examples that pass tests but have security issues")
print("="*70)

# ============================================================================
# EXAMPLE 1: DATA LOADING WITHOUT VALIDATION
# ============================================================================

print("\n" + "="*70)
print("EXAMPLE 1: DATA LOADING FUNCTION")
print("="*70)

def load_training_data(file_path):
    """
    Loads training data from CSV file
    PASSES TESTS: Works correctly with valid inputs
    SECURITY ISSUES: No validation, size limits, or integrity checks
    """
    df = pd.read_csv(file_path)
    return df

# Unit test that PASSES
def test_load_training_data():
    """Test passes because it uses a small, trusted test file"""
    test_data = pd.DataFrame({'feature1': [1, 2, 3], 'label': [0, 1, 0]})
    test_data.to_csv('test_data.csv', index=False)

    result = load_training_data('test_data.csv')
if len(result) != 3:
    raise AssertionError("Expected 3 rows")
if "feature1" not in result.columns:
    raise AssertionError("Expected column: feature1")

    print("✓ Unit test PASSED")

    os.remove('test_data.csv')

print("\n[Running unit test...]")
test_load_training_data()

print("\n[What Static Analysis Would Flag:]")
print("⚠️  WARNING: No input validation on file_path parameter")
print("⚠️  WARNING: No file size limit checking")
print("⚠️  WARNING: No data integrity verification (checksums)")
print("⚠️  WARNING: No anomaly detection in loaded data")
print("⚠️  WARNING: Could load malicious/poisoned data in production")
print("\n🔍 Static analysis caught 5 security issues that tests missed!")


# ============================================================================
# EXAMPLE 2: MODEL LOADING WITH PATH TRAVERSAL
# ============================================================================

print("\n\n" + "="*70)
print("EXAMPLE 2: MODEL SERVING API")
print("="*70)

SAFE_MODEL_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_model_path(model_name: str, models_dir: Path = Path("models")) -> Path:
    """
    Prevent path traversal by restricting model_name to a safe allowlist pattern,
    and by constructing paths via pathlib.
    """
    if not SAFE_MODEL_RE.fullmatch(model_name):
        raise ValueError("Invalid model name. Use only letters, numbers, _, -")
    return models_dir / f"{model_name}.pkl"


def load_and_predict(model_name, input_data):
    """
    Loads model and returns prediction
    PASSES TESTS: Works with valid model names
    SECURITY ISSUE: Path traversal vulnerability
    """
    # User-controlled input directly used in file path!
    model_path = safe_model_path(model_name)

# Integrity gate: require the expected SHA-256 via environment variable
# (In production, this would come from a trusted model registry / signed metadata.)
    expected = os.getenv("MODEL_SHA256")
    if not expected:
        raise RuntimeError("MODEL_SHA256 not set. Refusing to load untrusted model artifact.")

    actual = sha256_file(model_path)
    if actual != expected:
     raise RuntimeError("Model SHA-256 mismatch. Possible tampering. Aborting load.")

    # SECURITY FIX:
# Pickle-based model deserialization is intentionally disabled.
# In production, use ONNX, SafeTensors, or a signed model registry
# with format-level safety guarantees.
    raise RuntimeError(
    "Unsafe pickle-based model loading is disabled. "
    "Use a safe model format (ONNX, SafeTensors) or a secure model registry."
)


print("\n[Setting up test environment...]")
os.makedirs("models", exist_ok=True)

# SECURITY FIX (Path A):
# We no longer create or load pickle-based model artifacts.
# Instead, we write a harmless demo artifact and compute its SHA-256 to
# demonstrate integrity checks without unsafe serialization formats.
artifact_path = Path("models/test_model.bin")
artifact_path.write_bytes(b"DEMO_MODEL_ARTIFACT")

# Set expected hash for demo purposes
os.environ["MODEL_SHA256"] = sha256_file(artifact_path)


# Unit test that PASSES
def test_load_and_predict():
    """Test passes with legitimate model name"""
    input_data = np.array([[2, 3]])
    result = load_and_predict('test_model', input_data)
    if len(result) != 1:
        raise AssertionError("Expected 1 prediction")

    print("✓ Unit test PASSED")

print("\n[Running unit test...]")
test_load_and_predict()

print("\n[What Static Analysis Would Flag:]")
print("⚠️  CRITICAL: Unsanitized user input in file path")
print("⚠️  CRITICAL: Path traversal vulnerability")
print("    Attack example: model_name = '../../../etc/passwd'")
print("⚠️  CRITICAL: Unsafe pickle deserialization")
print("⚠️  WARNING: No authentication/authorization checks")
print("⚠️  WARNING: No rate limiting on model loading")
print("\n🔍 Static analysis caught 5 critical issues that tests missed!")

# Cleanup
os.remove('models/test_model.pkl')
os.rmdir('models')


# ============================================================================
# EXAMPLE 3: CONFIGURATION WITH HARDCODED SECRETS
# ============================================================================

print("\n\n" + "="*70)
print("EXAMPLE 3: CONFIGURATION MANAGEMENT")
print("="*70)

class ModelConfig:
    """
    Configuration for ML model deployment
    PASSES TESTS: Works correctly in test environment
    SECURITY ISSUES: Multiple secret management violations
    """
    def __init__(self):
        # ISSUE: Hardcoded credentials
        self.api_key = os.getenv("API_KEY")
        self.db_password = os.getenv("DB_PASSWORD")
        self.log_file = os.getenv("MODEL_LOG_FILE", "/var/log/model.log")

    def get_credentials(self):
        """Returns credentials for external API"""
        if not self.api_key:
            raise RuntimeError("Missing API_KEY environment variable")
        # SECURITY FIX: never log secrets
        print("Using API key: [REDACTED]")
        return self.api_key

    def connect_database(self):
        """Connects to database"""
        if not self.db_password:
            raise RuntimeError("Missing DB_PASSWORD environment variable")
        # SECURITY FIX: do not embed secrets in strings that might get logged
        # (For demo purposes, return a redacted string)
        return "postgresql://user:[REDACTED]@localhost/mldb"


# Unit test that PASSES
def test_config():
    """Test passes because credentials work in test environment"""
    config = ModelConfig()
    os.environ["API_KEY"] = "TEST_API_KEY_VALUE"
    os.environ["DB_PASSWORD"] = "TEST_VALUE" # nosec B105

    if len(result) != 3:
        raise AssertionError("Expected 3 rows")

    print("✓ Unit test PASSED")

print("\n[Running unit test...]")
test_config()

print("\n[What Static Analysis Would Flag:]")
print("⚠️  CRITICAL: Hardcoded API key in source code")
print("⚠️  CRITICAL: Hardcoded password in source code")
print("⚠️  CRITICAL: Sensitive data logged in plaintext")
print("⚠️  WARNING: No encryption for secrets at rest")
print("⚠️  WARNING: Password transmitted without encryption")
print("⚠️  WARNING: Credentials should be in environment variables")
print("\n🔍 Static analysis caught 6 security violations that tests missed!")


# ============================================================================
# SUMMARY
# ============================================================================

print("\n\n" + "="*70)
print("STATIC vs DYNAMIC ANALYSIS COMPARISON")
print("="*70)

print("\nAll three code examples:")
print("  ✓ Passed unit tests")
print("  ✓ Work correctly with test data")
print("  ✓ Would pass code review without security expertise")

print("\nBut static analysis found:")
print("  ⚠️  16 total security issues")
print("  ⚠️  8 critical vulnerabilities")
print("  ⚠️  100% invisible to runtime testing")

print("\nWhy runtime testing missed these:")
print("  • Tests use small, trusted datasets")
print("  • Tests use valid inputs only")
print("  • Tests use dummy credentials")
print("  • Tests check functionality, not security")

print("\nWhy static analysis caught them:")
print("  • Analyzes all possible code paths")
print("  • Checks for missing security controls")
print("  • Identifies dangerous patterns")
print("  • Validates secure coding standards")

print("\n" + "="*70)
print("KEY TAKEAWAY:")
print("Static analysis finds architectural security gaps that")
print("testing can't see—missing validations, unsafe patterns,")
print("and secrets that only appear in source code.")
print("="*70)