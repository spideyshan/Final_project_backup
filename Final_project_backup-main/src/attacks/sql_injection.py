# src/attacks/sql_injection.py
def vulnerable_login(query_string):
    """
    Toy simulation of a vulnerable login handling.
    """
    users = [{"username":"alice","password":"alicepass"}, {"username":"admin","password":"adminpass"}]
    s = query_string.lower()
    if "or 1=1" in s or "or '1'='1'" in s or "--" in s:
        return {"status":"OK","user":users[0], "note":"injection bypass simulated"}
    for u in users:
        if f"username={u['username']}" in s:
            return {"status":"OK","user":u}
    return {"status":"FAIL"}
