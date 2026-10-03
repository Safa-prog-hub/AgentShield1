def verify_response(response_result):
    """
    Verify whether the requested response was successfully executed.
    """

    if response_result.get("response_status") == "EXECUTED":
        return {
            "verification_status": "VERIFIED",
            "verified_action": response_result.get("action"),
            "target": response_result.get("target"),
            "message": "Response execution verified successfully"
        }

    return {
        "verification_status": "FAILED",
        "verified_action": None,
        "target": response_result.get("target"),
        "message": "Response execution could not be verified"
    }