"""A folder link planted inside the published folder is never followed: the status, reports and snapshots folders and
each report folder are opened by descriptor, one step at a time, without following a symbolic link."""
import os
import shutil

from app import published as pubm, snapshot
from test_jobs import finish


def _move_behind_a_link(path, outside):
    """Move the real folder at path to outside and leave a symbolic link to it in its place."""
    shutil.move(path, outside)
    os.symlink(outside, path)


def test_a_linked_status_folder_is_not_read(published, settings, tmp_path):
    finish(settings, "full-9", "done", "full")
    assert published_status_ok(settings, "full-9")
    _move_behind_a_link(os.path.join(settings.published_dir, "status"), str(tmp_path / "elsewhere-status"))
    assert pubm.job_status(settings.published_dir, "full-9") is None
    assert pubm.all_status(settings.published_dir) == []


def published_status_ok(settings, jid):
    st = pubm.job_status(settings.published_dir, jid)
    return st is not None and st["state"] == "done" and any(x["job_id"] == jid for x in pubm.all_status(settings.published_dir))


def test_a_linked_report_folder_is_neither_listed_nor_served(admin, published, tmp_path):
    assert admin.get("/runs/full-2/files/full-2.html").status_code == 200
    assert pubm.report_files(published, "full-2")
    _move_behind_a_link(os.path.join(published, "reports", "full-2"), str(tmp_path / "elsewhere-run"))
    assert admin.get("/runs/full-2/files/full-2.html").status_code == 404
    assert pubm.report_files(published, "full-2") == []


def test_a_linked_reports_folder_is_not_served(admin, published, tmp_path):
    _move_behind_a_link(os.path.join(published, "reports"), str(tmp_path / "elsewhere-reports"))
    assert admin.get("/runs/full-2/files/full-2.html").status_code == 404
    assert pubm.report_files(published, "full-2") == []


def test_a_linked_snapshots_folder_is_refused(published, settings, tmp_path):
    assert snapshot.current(published, settings.snapshot_cache).kind == "ok"
    snapshot._checked.clear()
    _move_behind_a_link(os.path.join(published, "snapshots"), str(tmp_path / "elsewhere-snapshots"))
    assert snapshot.current(published, settings.snapshot_cache).kind == "bad-pointer"
