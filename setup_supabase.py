import os
import sys
import time

try:
    from supabase import create_client, Client
except ImportError:
    print("❌ 'supabase' library not found. Please run: pip install supabase")
    sys.exit(1)

# ==============================================================================
# CONFIGURATION
# ==============================================================================
# Extracted from User Request
PROJECT_REF = "pybgyjuonordoljnogdt"
SUPABASE_URL = f"https://{PROJECT_REF}.supabase.co"

# User provided keys:
# Service Role (Secret) - Used for Admin Setup
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB5Ymd5anVvbm9yZG9sam5vZ2R0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2NjU0ODU5NywiZXhwIjoyMDgyMTI0NTk3fQ.Y9HSup8XwwcIVXrJ09zEM1UQqmIKWC6ED5vnSzdeUhQ"

# SQL DEFINITIONS (For Adaptive Subnet Clustering)
SQL_SETUP = """
-- 1. Create Threat Intel Table
create table if not exists threat_intel (
  id uuid default gen_random_uuid() primary key,
  ip_address inet not null,
  subnet inet generated always as (set_masklen(ip_address, 24)) stored,
  reporter_id uuid not null,
  created_at timestamptz default now()
);

-- 2. Create Active Bans Table
create table if not exists active_bans (
  cidr inet primary key,
  risk_level text check (risk_level in ('CRITICAL', 'WARNING')),
  reason text,
  expires_at timestamptz
);

-- 3. Create Profiles Table (Linked to Auth)
create table if not exists profiles (
  id uuid references auth.users on delete cascade primary key,
  email text,
  username text,
  full_name text,
  avatar_url text,
  updated_at timestamptz
);

-- 4. Enable Row Level Security (RLS)
alter table threat_intel enable row level security;
alter table active_bans enable row level security;
alter table profiles enable row level security;

-- 5. Policy: Anyone can insert threats (Anon Key)
create policy "Allow Anonymous Reporting"
on threat_intel for insert
with check (true);

-- 6. Policy: Everyone can read bans
create policy "Public Read Bans"
on active_bans for select
using (true);

-- 7. Policy: Users can update their own profile
create policy "Users can update own profile"
on profiles for update
using (auth.uid() = id);

-- 8. Policy: Profiles are viewable by everyone
create policy "Public profiles"
on profiles for select
using (true);

-- 9. Trigger to create profile on signup
-- Function to handle new user
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, full_name, username)
  values (new.id, new.email, new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'username');
  return new;
end;
$$ language plpgsql security definer;

-- Trigger logic (uncomment to enable if you have permissions)
-- create trigger on_auth_user_created
--   after insert on auth.users
--   for each row execute procedure public.handle_new_user();
"""

def main():
    print("==========================================")
    print("   SUPABASE CLOUD DEFENSE SETUP SCIPT     ")
    print("==========================================")
    
    url = SUPABASE_URL
    key = SUPABASE_KEY
    
    if not url or not key:
        print("\n⚠️  Credentials not found in environment variables.")
        url = input("Enter Supabase URL: ").strip()
        key = input("Enter Supabase Key (Service/Anon): ").strip()
    
    if not url or not key:
        print("❌ Error: Missing Credentials. Aborting.")
        return

    print(f"\nCONNECTING to {url}...")
    try:
        supabase: Client = create_client(url, key)
        print("✅ Connection Successful!")
        
        # NOTE: The Supabase Client (PostgREST) cannot execute raw SQL DDL (CREATE TABLE).
        # To automate this from a script without a Postgres driver (psycopg2), 
        # we typically use the SQL Editor in the Dashboard.
        # However, if you have the 'service_role' key, some admin APIs might be available,
        # or we might need to use a Postgres connection string.
        
        print("\nINSTRUCTION: Run the following SQL in your Supabase SQL Editor:")
        print("---------------------------------------------------------------")
        print(SQL_SETUP)
        print("---------------------------------------------------------------")
        
        print("\n[Simulation] Checking for existing tables (via API)...")
        try:
            # Try to select from table to see if it exists
            response = supabase.table("active_bans").select("*").limit(1).execute()
            print("✅ 'active_bans' table exists or is accessible.")
        except Exception as e:
            print(f"ℹ️  Could not access 'active_bans'. It likely needs to be created.\nError: {e}")

    except Exception as e:
        print(f"❌ Connection Failed: {e}")

if __name__ == "__main__":
    main()
