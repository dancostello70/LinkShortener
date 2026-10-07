import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

import app as link_app


class AppReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.temp_dir.name, 'links.db')
        self.original_database = link_app.DATABASE
        link_app.DATABASE = self.database
        self.config_patch = patch.object(link_app.config, 'FORCE_HTTPS', False)
        self.config_patch.start()
        link_app.app.config['TESTING'] = True
        link_app.init_db()
        self.client = link_app.app.test_client()

    def tearDown(self):
        link_app.DATABASE = self.original_database
        self.config_patch.stop()
        link_app.app.config['TESTING'] = False
        self.temp_dir.cleanup()

    def test_pages_and_shortcut_redirect_work_over_http(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute(
                'INSERT INTO links (shortcode, url) VALUES (?, ?)',
                ('example', 'https://example.com/path'),
            )
            conn.commit()

        response = self.client.get('/example')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], 'https://example.com/path')

    def test_https_redirect_is_opt_in_and_honors_proxy_protocol(self):
        with patch.object(link_app.config, 'FORCE_HTTPS', True):
            response = self.client.get('/')
            self.assertEqual(response.status_code, 301)
            self.assertTrue(response.headers['Location'].startswith('https://'))

            response = self.client.get(
                '/', headers={'X-Forwarded-Proto': 'https'}
            )
            self.assertEqual(response.status_code, 200)

    def test_missing_and_invalid_shortcut_destinations_do_not_crash(self):
        with self.client.session_transaction() as session:
            session['user_id'] = 1

        response = self.client.post('/admin/add', data={})
        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            session['user_id'] = 1

        response = self.client.post(
            '/admin/add',
            data={'shortcode': 'unsafe', 'url': 'javascript://example.com'},
        )
        self.assertEqual(response.status_code, 302)

        with closing(sqlite3.connect(self.database)) as conn:
            count = conn.execute(
                'SELECT COUNT(*) FROM links WHERE shortcode = ?', ('unsafe',)
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_deleted_user_session_is_invalidated(self):
        with self.client.session_transaction() as session:
            session['user_id'] = 99999
            session['is_admin'] = True

        response = self.client.get('/admin')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/admin/login'))

        with self.client.session_transaction() as session:
            self.assertNotIn('user_id', session)

    def test_legacy_user_schema_migrates_without_suppressing_errors(self):
        legacy_database = os.path.join(self.temp_dir.name, 'legacy.db')
        link_app.DATABASE = legacy_database
        with closing(sqlite3.connect(legacy_database)) as conn:
            conn.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            ''')
            conn.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                ('legacy', 'placeholder'),
            )
            conn.commit()

        link_app.init_db()

        with closing(sqlite3.connect(legacy_database)) as conn:
            columns = {
                row[1] for row in conn.execute('PRAGMA table_info(users)').fetchall()
            }
            legacy_user = conn.execute(
                'SELECT is_admin, created_at, last_login FROM users WHERE username = ?',
                ('legacy',),
            ).fetchone()
        self.assertTrue({'is_admin', 'created_at', 'last_login'} <= columns)
        self.assertEqual(legacy_user[0], 1)
        self.assertIsNotNone(legacy_user[1])


if __name__ == '__main__':
    unittest.main()
