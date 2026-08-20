from __future__ import annotations

from calendar import monthrange
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from typing import Literal, Self

from dateutil.tz import datetime_exists, gettz, resolve_imaginary
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .run_models import RunRequest, _normalize_target

MAX_SCHEDULE_TARGETS = 10_000
ScheduleFrequency = Literal['once', 'hourly', 'daily', 'weekly', 'monthly']
OverlapPolicy = Literal['skip', 'queue']
DispatchState = Literal['reserved', 'queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled']


def utc_now_datetime() -> datetime:
    return datetime.now(UTC)


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('datetime must include a UTC offset')
    return value.astimezone(UTC).isoformat()


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError('stored datetime must include a UTC offset')
    return parsed.astimezone(UTC)


def _timezone(name: str) -> tzinfo:
    zone = gettz(name)
    if zone is None:
        raise ValueError('timezone must be a valid IANA timezone')
    return zone


def _wall_candidate(day: date, wall_time: time, zone: tzinfo) -> datetime:
    """Build a local wall-clock candidate and normalize a nonexistent DST time forward."""
    candidate = datetime.combine(day, wall_time, tzinfo=zone)
    return candidate if datetime_exists(candidate) else resolve_imaginary(candidate)


class ScheduleTiming(BaseModel):
    """A small, UI-friendly recurrence model with timezone-aware calendar behavior."""

    model_config = ConfigDict(extra='forbid')

    frequency: ScheduleFrequency = Field(description='Run once, hourly, daily, weekly, or monthly.')
    start_at: datetime = Field(description='First eligible run time. An explicit UTC offset is required.')
    timezone: str = Field(default='UTC', description='IANA timezone used for calendar wall-clock recurrence.')
    interval: int = Field(default=1, ge=1, le=365, description='Number of frequency units between occurrences.')
    weekdays: list[int] = Field(
        default_factory=list,
        max_length=7,
        description='Weekly ISO weekdays, where Monday is 1 and Sunday is 7.',
    )

    @field_validator('start_at')
    @classmethod
    def require_aware_start(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('start_at must include a UTC offset')
        return value

    @field_validator('timezone')
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        timezone = value.strip()
        _timezone(timezone)
        return timezone

    @field_validator('weekdays')
    @classmethod
    def validate_weekdays(cls, values: list[int]) -> list[int]:
        if any(value < 1 or value > 7 for value in values):
            raise ValueError('weekdays must contain ISO weekday numbers from 1 through 7')
        if len(values) != len(set(values)):
            raise ValueError('weekdays must not contain duplicates')
        return sorted(values)

    @model_validator(mode='after')
    def validate_frequency_options(self) -> Self:
        if self.frequency == 'weekly' and not self.weekdays:
            self.weekdays = [self.start_at.astimezone(_timezone(self.timezone)).isoweekday()]
        elif self.frequency != 'weekly' and self.weekdays:
            raise ValueError('weekdays may be set only for weekly schedules')
        if self.frequency == 'once' and self.interval != 1:
            raise ValueError('once schedules must use interval 1')
        return self

    def first_due_at(self) -> datetime:
        start = self.start_at.astimezone(UTC)
        if self.frequency != 'weekly' or self.start_at.astimezone(_timezone(self.timezone)).isoweekday() in self.weekdays:
            return start
        first = self.next_after(start)
        assert first is not None
        return first

    def next_after(self, after: datetime) -> datetime | None:
        """Return the first occurrence strictly after ``after``.

        Daily, weekly, and monthly schedules preserve local wall-clock time across DST.
        Hourly schedules intentionally use elapsed UTC hours.
        """
        if after.tzinfo is None or after.utcoffset() is None:
            raise ValueError('after must include a UTC offset')
        after_utc = after.astimezone(UTC)
        start_utc = self.start_at.astimezone(UTC)

        if self.frequency == 'once':
            return start_utc if start_utc > after_utc else None

        if self.frequency == 'hourly':
            step = timedelta(hours=self.interval)
            if after_utc < start_utc:
                return start_utc
            completed_steps = (after_utc - start_utc) // step
            return start_utc + step * (completed_steps + 1)

        zone = _timezone(self.timezone)
        local_start = self.start_at.astimezone(zone)
        local_after = after_utc.astimezone(zone)
        wall_time = local_start.timetz().replace(tzinfo=None)

        if self.frequency == 'daily':
            day_offset = max(0, (local_after.date() - local_start.date()).days)
            aligned_offset = day_offset - (day_offset % self.interval)
            candidate_day = local_start.date() + timedelta(days=aligned_offset)
            candidate = _wall_candidate(candidate_day, wall_time, zone)
            if candidate.astimezone(UTC) <= after_utc or candidate < local_start:
                candidate_day += timedelta(days=self.interval)
                candidate = _wall_candidate(candidate_day, wall_time, zone)
            return candidate.astimezone(UTC)

        if self.frequency == 'monthly':
            start_month = local_start.year * 12 + local_start.month - 1
            after_month = local_after.year * 12 + local_after.month - 1
            elapsed_months = max(0, after_month - start_month)
            aligned_months = elapsed_months - (elapsed_months % self.interval)
            candidate_month = start_month + aligned_months
            year, month_index = divmod(candidate_month, 12)
            month = month_index + 1
            candidate_day = date(year, month, min(local_start.day, monthrange(year, month)[1]))
            candidate = _wall_candidate(candidate_day, wall_time, zone)
            if candidate.astimezone(UTC) <= after_utc or candidate < local_start:
                year, month_index = divmod(candidate_month + self.interval, 12)
                month = month_index + 1
                candidate_day = date(year, month, min(local_start.day, monthrange(year, month)[1]))
                candidate = _wall_candidate(candidate_day, wall_time, zone)
            return candidate.astimezone(UTC)

        start_week = local_start.date() - timedelta(days=local_start.isoweekday() - 1)
        after_week = local_after.date() - timedelta(days=local_after.isoweekday() - 1)
        elapsed_weeks = max(0, (after_week - start_week).days // 7)
        aligned_week = elapsed_weeks - (elapsed_weeks % self.interval)
        week_start = start_week + timedelta(weeks=aligned_week)

        for week_jump in range(0, self.interval * 2 + 1, self.interval):
            candidate_week = week_start + timedelta(weeks=week_jump)
            for weekday in self.weekdays:
                candidate_day = candidate_week + timedelta(days=weekday - 1)
                candidate = _wall_candidate(candidate_day, wall_time, zone)
                if candidate >= local_start and candidate.astimezone(UTC) > after_utc:
                    return candidate.astimezone(UTC)
        raise RuntimeError('could not calculate the next weekly schedule occurrence')

    def next_future_after(self, occurrence: datetime, now: datetime | None = None) -> datetime | None:
        """Advance after an occurrence and coalesce missed times after downtime."""
        reference = max(occurrence.astimezone(UTC), (now or utc_now_datetime()).astimezone(UTC))
        return self.next_after(reference)

    def upcoming_occurrences(
        self,
        first: datetime | None,
        *,
        limit: int = 5,
        now: datetime | None = None,
    ) -> list[datetime]:
        if first is None or limit < 1:
            return []
        occurrences = [first.astimezone(UTC)]
        current = self.next_future_after(first, now)
        while current is not None and len(occurrences) < limit:
            occurrences.append(current.astimezone(UTC))
            current = self.next_after(current)
        return occurrences


class ScheduleCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str = Field(min_length=1, max_length=120)
    targets: list[str] = Field(min_length=1, max_length=MAX_SCHEDULE_TARGETS)
    run: RunRequest = Field(description='Validated run template. Its target is replaced for every scheduled target.')
    timing: ScheduleTiming
    enabled: bool = True
    overlap_policy: OverlapPolicy = Field(
        default='skip',
        description='Skip an occurrence while a prior batch remains active, or queue another batch.',
    )

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = ' '.join(value.split())
        if not normalized:
            raise ValueError('name must not be blank')
        return normalized

    @field_validator('targets')
    @classmethod
    def normalize_targets(cls, values: list[str]) -> list[str]:
        normalized = [_normalize_target(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError('targets must not contain duplicates')
        return normalized

    @model_validator(mode='after')
    def validate_run_for_every_target(self) -> Self:
        template = self.run.model_dump()
        validated: list[str] = []
        for target in self.targets:
            request = RunRequest.model_validate({**template, 'target': target})
            validated.append(request.target)
        self.targets = validated
        self.run = RunRequest.model_validate({**template, 'target': validated[0]})
        return self


class ScheduleResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    schedule_id: str
    name: str
    targets: list[str]
    run: RunRequest
    timing: ScheduleTiming
    enabled: bool
    overlap_policy: OverlapPolicy
    created_at: str
    updated_at: str
    next_run_at: str | None
    upcoming_occurrences: list[str]
    last_run_at: str | None
    last_error: str | None


class ScheduleDispatchResponse(BaseModel):
    schedule_id: str
    scheduled_for: str
    run_ids: list[str]
    skipped_targets: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ScheduleHealthResponse(BaseModel):
    scheduler_enabled: bool
    scheduler_available: bool
    worker_enabled: bool
    worker_available: bool


class ScheduleDispatchRecord(BaseModel):
    dispatch_id: str
    schedule_id: str
    scheduled_for: str
    target: str
    run_id: str
    state: DispatchState
    error: str | None
    created_at: str
    updated_at: str
