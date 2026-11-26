"""Momus brain: the web application that writes job files and reads published scan results.

It never sends anything to a scan target. It shares no network with the scanner; the two exchange files through
the jobs folder (written here) and the published folder (read-only here).
"""
