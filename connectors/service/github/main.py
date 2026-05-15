import asyncio
import time
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from itertools import batched

import git.exc
from aiofiles import tempfile
from git import Repo

from sdk import Scheduler, VulnCommanderSDK
from sdk.src.utils import GrayLogLogger, get_running_loop
from shared.schemas.constants import ProjectStatus, UserTeam
from shared.schemas.project import CommitMetadataSchema, ProjectMetadataSchema, ProjectSchema

from config import Config


class GitHubService:
    def __init__(self) -> None:
        self._processed_projects = 0
        self._skipped_projects = 0

    async def run(self) -> None:
        async with VulnCommanderSDK(Config.CONNECTOR_ID, Config.CONNECTOR_PASSWORD) as sdk:
            with open(Config.PROJECTS_PATH, 'r') as file:
                projects = file.read().split('\n')
                for chunk in batched(projects, Config.PARALLEL_TASKS_COUNT):
                    for repo_clone_url in chunk:
                        tasks = [asyncio.create_task(self._create_or_update_project_info(sdk, repo_clone_url))]

                    await asyncio.gather(*tasks)
                    tasks.clear()

                    log.logger.info(
                        f'Processed {self._processed_projects}/{len(projects)}. '
                        f'Skipped: {self._skipped_projects}'
                    )

    async def _create_or_update_project_info(self, sdk: VulnCommanderSDK, clone_url: str) -> None:
        async with tempfile.TemporaryDirectory() as temp_dir:
            loop = get_running_loop()
            with ThreadPoolExecutor() as pool:
                project_info: ProjectSchema = await loop.run_in_executor(
                    pool,
                    self._get_project_info,
                    clone_url,
                    temp_dir
                )

        if project_info:
            await sdk.create_or_update_project(project_info)
            await self._increment_projects_counter('processed')
            log.logger.info(f'Processed project: {project_info.project.name}')
        else:
            await self._increment_projects_counter('skipped')
            log.logger.info(f'Failed to process the project: {clone_url}')


    def _get_project_info(self, clone_url: str, temp_dir: str) -> ProjectSchema | None:
        try:
            repo = Repo.clone_from(clone_url, temp_dir)
        except git.exc.GitError:
            return

        if repo.bare:
            log.logger.info(f'Repository {clone_url} is empty!')
            return

        project_clone_url = next(repo.remote().urls)
        project_name = project_clone_url.split('/')[-1].split('.')[0]

        try:
            project_default_branch = repo.remote().refs['HEAD'].ref.name.split('/')[-1]
        except Exception:
            project_default_branch = repo.active_branch.name

        last_commit = repo.head.commit

        last_commit_author = last_commit.author.name
        last_commit_email = last_commit.author.email
        last_commit_created_at = datetime.fromtimestamp(last_commit.committed_date)
        last_commit_hash = last_commit.hexsha

        return ProjectSchema(
                project=ProjectMetadataSchema(
                    team=random.choice([UserTeam.ti, UserTeam.sandbox]),
                    name=project_name,
                    status=ProjectStatus.active,
                    default_branch=project_default_branch,
                    clone_url=project_clone_url
                ),
                last_commit=CommitMetadataSchema(
                    author=last_commit_author,
                    email=last_commit_email,
                    created_at=last_commit_created_at,
                    hash=last_commit_hash
                )
            )

    async def _increment_projects_counter(self, project_type: str) -> None:
        if project_type == 'processed':
            self._processed_projects += 1
        else:
            self._skipped_projects += 1


if __name__ == '__main__':
    time.sleep(5)
    service = GitHubService()
    log = GrayLogLogger(Config.GRAYLOG_UDP_PORT)
    for next_run in Scheduler(Config.CRON_SCHEDULE):
        log.logger.info('Connector started')
        asyncio.run(service.run())
        log.logger.info(f'Successful run. Next run at: {next_run}')
