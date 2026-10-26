# Dataset notes

The supplied archive contains `raw/PhiUSIIL_Phishing_URL_Dataset.csv` (235,795 rows; 55 columns). PhishGuard uses only `URL` and `label` from this file and extracts its own URL-derived features so training and API inference share the same schema.

Before publishing the dataset in a public repository, verify the original dataset's license and redistribution terms. If redistribution is not permitted, remove the CSV from Git, document the original source and provide a local placement/download step instead. The CSV is included in this working bundle because it was supplied by the project owner.
