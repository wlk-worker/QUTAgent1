"""Local process-isolated Web lab for QUTAgent (standard library only).

Modules:
- ``target``: deliberately vulnerable authorized Web challenge with a dynamic flag.
- ``mock_platform``: minimal CTFy-compatible REST stand-in that really checks flags.
- ``fake_model``: scripted but observation-driven OpenAI-compatible model server.
- ``runner``: starts the three servers as child processes and records evidence.
"""
