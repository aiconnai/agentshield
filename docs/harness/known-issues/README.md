# Known-Issue Sensor Exclusions

Sensor exclusions are allowed only for documented known issues. They are not a way to make production code look green.

Each exclusion must include:

- specific sensor name;
- known issue file path;
- short reason;
- progress registration before relying on the exclusion.

Use this command shape:

```bash
bash docs/harness/bin/sensors.sh full \
  --exclude-sensor <name> \
  --known-issue docs/harness/known-issues/<issue>.md \
  --reason "short factual reason"
```

The known-issue file should record:

| Field | Meaning |
|---|---|
| Sensor | Sensor or lane being excluded |
| Reason | Why the exclusion is needed |
| Owner | Person or team responsible for removing it |
| First seen | Date |
| Removal condition | What must become true before deleting the exclusion |
| Verification impact | What evidence is missing while excluded |
