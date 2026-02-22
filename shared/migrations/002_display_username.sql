CREATE TABLE user_profiles (
	user_id UUID PRIMARY KEY,
	display_name TEXT,
	bio TEXT,
	
	CONSTRAINT fk_user_profile 
        FOREIGN KEY (user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE

);