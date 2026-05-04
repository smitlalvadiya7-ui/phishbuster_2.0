import os

def get_ai_verdict(url, heuristic, vt_result, gsb_result, domain_info):
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key == "your_key_here":
        return "AI analysis unavailable - API key not set."

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        prompt = f"""You are a cybersecurity expert analyzing a URL for phishing.

URL: {url}

Evidence:
- Heuristic Risk Score: {heuristic['heuristic_score']}/100
- Flags: {', '.join(heuristic['reasons']) if heuristic['reasons'] else 'None'}
- VirusTotal: {vt_result.get('malicious', 0)} malicious out of {vt_result.get('total', 0)} engines
- Google Safe Browsing: {'UNSAFE - ' + str(gsb_result['threats']) if not gsb_result['safe'] else 'Clean'}
- Domain Age: {domain_info.get('age_days', 'Unknown')} days
- Registrar: {domain_info.get('registrar', 'Unknown')}

Give:
1. Final verdict: SAFE, SUSPICIOUS, or MALICIOUS
2. 2-3 sentence plain English explanation for non-technical users
3. One action the user should take

Be concise. No markdown."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    except Exception as e:
        return f"AI analysis error: {str(e)}"
