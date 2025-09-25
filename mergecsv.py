import os
import glob
import pandas as pd

def merge_csv_files(output_filename="merged.csv"):
    # Find all CSV files in the current directory
    csv_files = glob.glob(os.path.join(os.getcwd(), "*.csv"))
    
    if not csv_files:
        print("No CSV files found in the current directory.")
        return

    # Read and combine all CSVs
    df_list = []
    for file in csv_files:
        print(f"Reading {file}...")
        df = pd.read_csv(file)
        df_list.append(df)

    merged_df = pd.concat(df_list, ignore_index=True)

    # Save the merged file
    merged_df.to_csv(output_filename, index=False)
    print(f"Merged {len(csv_files)} files into {output_filename}")

if __name__ == "__main__":
    merge_csv_files("merged.csv")
