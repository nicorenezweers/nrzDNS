-- nrzNetwork: die Sperrseite wird der Standard-Sperrmodus. Wer noch den alten Standard
-- (0.0.0.0) hatte, bekommt die Sperrseite; eine bewusst andere Wahl bleibt.
UPDATE app_settings
SET value = json_set(value, '$.blockMode', 'blockPage')
WHERE key = 'dns' AND json_extract(value, '$.blockMode') = 'nullAddress';
