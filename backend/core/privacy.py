"""Role-specific presentation masking. Preserved evidence is never rewritten."""
import re

REDACT = {'body', 'html_body', 'model_text', 'raw_headers', 'raw_header', 'headers',
          'display_name', 'original_filename', 'plain_text_body', 'html_text', 'raw',
          'original_bytes', 'subject', 'notes'}
INTEGRITY = {'sha256', 'content_hash', 'evidence_hashes'}


def mask_sensitive(value, key=None):
    if key in REDACT:
        return '[Masked by privacy policy]'
    if key in INTEGRITY:
        return value
    if isinstance(value, dict):
        return {k: mask_sensitive(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_sensitive(v, key) for v in value]
    if isinstance(value, str):
        value = re.sub(r'[\w.+-]+@[\w.-]+', '[masked email]', value)
        # Preserve hex digests and resource identifiers. Raw content containing
        # arbitrary personal information is removed above, not merely regexed.
        if re.fullmatch(r'[a-fA-F0-9]{32,128}', value) or key in ('id', '_id', 'email_id', 'case_id', 'evidence_id', 'job_id'):
            return value
        value = re.sub(r'https?://[^\s<>]+', '[masked URL]', value)
        return re.sub(r'(?<![\w.])\+?\d[\d ()-]{8,}\d(?![\w.])', '[masked number]', value)
    return value
