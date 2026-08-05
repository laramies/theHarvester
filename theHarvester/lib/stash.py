import datetime
import logging
import os
from collections.abc import Iterable
from sqlite3.dbapi2 import Row
from typing import cast
from uuid import UUID

import aiosqlite

from theHarvester.lib.completed_result import CompletedResult, ResultKind

logger = logging.getLogger(__name__)


db_path = os.path.expanduser('~/.local/share/theHarvester')

if not os.path.isdir(db_path):
    os.makedirs(db_path)


class StashManager:
    def __init__(self) -> None:
        self.db = os.path.join(db_path, 'stash.sqlite')
        self.results = ''
        self.totalresults = ''
        self.latestscandomain: dict = {}
        self.domainscanhistory: list = []
        self.scanboarddata: dict = {}
        self.scanstats: list = []
        self.latestscanresults: list = []
        self.previousscanresults: list = []

    @staticmethod
    def _col0_int(row: Row | None) -> int:
        try:
            val = row[0] if row is not None else None
            return int(val) if val is not None else 0
        except Exception:
            return 0

    @staticmethod
    def _col0_value(row: Row | None):
        return row[0] if row is not None else None

    async def do_init(self) -> None:
        async with aiosqlite.connect(self.db) as db:
            await db.execute('PRAGMA foreign_keys = ON')
            await db.execute(
                'CREATE TABLE IF NOT EXISTS results (domain text, resource text, type text, find_date date, source text)'
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS completed_results (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS completed_result_items (
                    run_id TEXT NOT NULL REFERENCES completed_results(run_id) ON DELETE CASCADE,
                    position INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (run_id, position),
                    UNIQUE (run_id, kind, value)
                )
                """
            )
            await db.commit()

    async def store_completed_result(self, result: CompletedResult) -> None:
        async with aiosqlite.connect(self.db, timeout=30) as db:
            await db.execute('PRAGMA foreign_keys = ON')
            try:
                await db.execute(
                    'INSERT INTO completed_results (run_id, target, started_at, completed_at) VALUES (?, ?, ?, ?)',
                    (
                        str(result.run_id),
                        result.target,
                        result.started_at.isoformat(),
                        result.completed_at.isoformat(),
                    ),
                )
                await db.executemany(
                    'INSERT INTO completed_result_items (run_id, position, kind, value) VALUES (?, ?, ?, ?)',
                    [(str(result.run_id), position, kind, value) for position, (kind, value) in enumerate(result.results)],
                )
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    async def load_completed_result(self, run_id: UUID) -> CompletedResult:
        async with aiosqlite.connect(self.db, timeout=30) as db:
            cursor = await db.execute(
                'SELECT run_id, target, started_at, completed_at FROM completed_results WHERE run_id = ?',
                (str(run_id),),
            )
            parent = await cursor.fetchone()
            if parent is None:
                raise LookupError(f'completed result not found: {run_id}')
            cursor = await db.execute(
                'SELECT kind, value FROM completed_result_items WHERE run_id = ? ORDER BY position',
                (str(run_id),),
            )
            rows = await cursor.fetchall()
        return CompletedResult(
            run_id=UUID(parent[0]),
            target=parent[1],
            started_at=datetime.datetime.fromisoformat(parent[2]),
            completed_at=datetime.datetime.fromisoformat(parent[3]),
            results=tuple((cast('ResultKind', kind), value) for kind, value in rows),
        )

    async def store(self, domain, resource, res_type, source) -> None:
        self.domain = domain
        self.resource = resource
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        try:
            async with aiosqlite.connect(self.db, timeout=30) as db:
                await db.execute(
                    'INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                    (self.domain, self.resource, self.type, self.date, self.source),
                )
                await db.commit()
        except Exception as e:
            logger.info(f'Unexpected error while storing result: {e}')

    async def store_all(self, domain, all, res_type, source) -> None:
        # people are not stored in the database
        if res_type == 'people':
            return

        self.domain = domain
        self.all = all
        self.type = res_type
        self.source = source
        self.date = datetime.date.today()
        master_list = [(self.domain, x, self.type, self.date, self.source) for x in self.all]
        async with aiosqlite.connect(self.db, timeout=30) as db:
            try:
                await db.executemany(
                    'INSERT INTO results (domain,resource, type, find_date, source) VALUES (?,?,?,?,?)',
                    master_list,
                )
                await db.commit()
            except Exception as e:
                logger.info(f'Unexpected error while storing result: {e}')

    async def generatedashboardcode(self, domain):
        try:
            # TODO refactor into generic method
            self.latestscandomain['domain'] = domain
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="host"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['host'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="email"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['email'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['ip'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['vhost'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['shodan'] = self._col0_int(data)
                cursor = await conn.execute("""SELECT MAX(find_date) FROM results WHERE domain=?""", (domain,))
                data = await cursor.fetchone()
                self.latestscandomain['latestdate'] = self._col0_value(data)
                latestdate = self._col0_value(data)
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailshost = await cursor.fetchall()
                self.latestscandomain['scandetailshost'] = scandetailshost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsemail = await cursor.fetchall()
                self.latestscandomain['scandetailsemail'] = scandetailsemail
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsip = await cursor.fetchall()
                self.latestscandomain['scandetailsip'] = scandetailsip
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsvhost = await cursor.fetchall()
                self.latestscandomain['scandetailsvhost'] = scandetailsvhost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsshodan = await cursor.fetchall()
                self.latestscandomain['scandetailsshodan'] = scandetailsshodan
            return self.latestscandomain
        except Exception as e:
            logger.info(f'Unexpected error while generating the dashboard code: {e}')

    async def getlatestscanresults(self, domain, previousday: bool = False) -> Iterable[Row | str] | None:
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                if previousday:
                    try:
                        cursor = await conn.execute(
                            """
                        SELECT DISTINCT(find_date)
                        FROM results
                        WHERE find_date=date('now', '-1 day') and domain=?""",
                            (domain,),
                        )
                        previousscandate = await cursor.fetchone()
                        prev_date = self._col0_value(previousscandate)
                        if not prev_date:  # When theHarvester runs first time/day, this query will return.
                            self.previousscanresults = [
                                'No results',
                                'No results',
                                'No results',
                                'No results',
                                'No results',
                            ]
                        else:
                            cursor = await conn.execute(
                                """
                            SELECT find_date, domain, source, type, resource
                            FROM results
                            WHERE find_date=? and domain=?
                            ORDER BY source,type
                            """,
                                (
                                    prev_date,
                                    domain,
                                ),
                            )
                            results = await cursor.fetchall()
                            self.previousscanresults = list(results)
                        return self.previousscanresults
                    except Exception as e:
                        logger.info(f'Error in getting the previous scan results from the database: {e}')
                else:
                    try:
                        cursor = await conn.execute(
                            """SELECT MAX(find_date) FROM results WHERE domain=?""",
                            (domain,),
                        )
                        latestscandate = await cursor.fetchone()
                        latest_date = self._col0_value(latestscandate)
                        cursor = await conn.execute(
                            """
                        SELECT find_date, domain, source, type, resource
                        FROM results
                        WHERE find_date=? and domain=?
                        ORDER BY source,type
                        """,
                            (
                                latest_date,
                                domain,
                            ),
                        )
                        results = await cursor.fetchall()
                        self.latestscanresults = list(results)
                        return self.latestscanresults
                    except Exception as e:
                        logger.info(f'Error in getting the latest scan results from the database: {e}')
        except Exception as e:
            logger.info(f'Error connecting to theHarvester database: {e}')
        return self.latestscanresults

    async def getscanboarddata(self):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="host"''')
                data = await cursor.fetchone()
                self.scanboarddata['host'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="email"''')
                data = await cursor.fetchone()
                self.scanboarddata['email'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="ip"''')
                data = await cursor.fetchone()
                self.scanboarddata['ip'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="vhost"''')
                data = await cursor.fetchone()
                self.scanboarddata['vhost'] = self._col0_int(data)
                cursor = await conn.execute('''SELECT COUNT(*) from results WHERE type="shodan"''')
                data = await cursor.fetchone()
                self.scanboarddata['shodan'] = self._col0_int(data)
                cursor = await conn.execute("""SELECT COUNT(DISTINCT(domain)) FROM results """)
                data = await cursor.fetchone()
                self.scanboarddata['domains'] = self._col0_int(data)
            return self.scanboarddata
        except Exception as e:
            logger.info(f'Unexpected error while getting the scanboard data: {e}')

    async def getscanhistorydomain(self, domain):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute(
                    """SELECT DISTINCT(find_date) FROM results WHERE domain=?""",
                    (domain,),
                )
                dates = await cursor.fetchall()
                for date in dates:
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="host" AND find_date=?""",
                        (domain, date[0]),
                    )
                    counthost = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="email" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countemail = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="ip" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countip = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="vhost" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countvhost = await cursor.fetchone()
                    cursor = await conn.execute(
                        """SELECT COUNT(*) from results WHERE domain=? AND type="shodan" AND find_date=?""",
                        (domain, date[0]),
                    )
                    countshodan = await cursor.fetchone()
                    results = {
                        'date': str(date[0]),
                        'hosts': str(self._col0_int(counthost)),
                        'email': str(self._col0_int(countemail)),
                        'ip': str(self._col0_int(countip)),
                        'vhost': str(self._col0_int(countvhost)),
                        'shodan': str(self._col0_int(countshodan)),
                    }
                    self.domainscanhistory.append(results)
            return self.domainscanhistory
        except Exception as e:
            logger.info(f'Unexpected error while getting the scanhistory of a domain: {e}')

    async def getpluginscanstatistics(self) -> Iterable[Row] | None:
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                cursor = await conn.execute(
                    """
                SELECT domain,find_date, type, source, count(*)
                FROM results
                GROUP BY domain, find_date, type, source
                """
                )
                results = await cursor.fetchall()
                self.scanstats = list(results)
        except Exception as e:
            logger.info(f'Unexpected error while getting a plugins scanstatistics: {e}')
        return self.scanstats

    async def latestscanchartdata(self, domain):
        try:
            async with aiosqlite.connect(self.db, timeout=30) as conn:
                self.latestscandomain['domain'] = domain
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="host"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['host'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="email"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['email'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="ip"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['ip'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="vhost"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['vhost'] = self._col0_int(data)
                cursor = await conn.execute(
                    '''SELECT COUNT(*) from results WHERE domain=? AND type="shodan"''',
                    (domain,),
                )
                data = await cursor.fetchone()
                self.latestscandomain['shodan'] = self._col0_int(data)
                cursor = await conn.execute("""SELECT MAX(find_date) FROM results WHERE domain=?""", (domain,))
                data = await cursor.fetchone()
                self.latestscandomain['latestdate'] = self._col0_value(data)
                latestdate = self._col0_value(data)
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="host"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailshost = await cursor.fetchall()
                self.latestscandomain['scandetailshost'] = scandetailshost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="email"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsemail = await cursor.fetchall()
                self.latestscandomain['scandetailsemail'] = scandetailsemail
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="ip"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsip = await cursor.fetchall()
                self.latestscandomain['scandetailsip'] = scandetailsip
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="vhost"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsvhost = await cursor.fetchall()
                self.latestscandomain['scandetailsvhost'] = scandetailsvhost
                cursor = await conn.execute(
                    '''SELECT * FROM results WHERE domain=? AND find_date=? AND type="shodan"''',
                    (
                        domain,
                        latestdate,
                    ),
                )
                scandetailsshodan = await cursor.fetchall()
                self.latestscandomain['scandetailsshodan'] = scandetailsshodan
            return self.latestscandomain
        except aiosqlite.Error as db_err:
            logger.info(f"Database error occurred for domain '{domain}': {db_err}")
        except Exception as e:
            logger.info(f"Unexpected error in latestscanchartdata for domain '{domain}': {e}")
