use std::sync::Arc;

use construct_context::AppContext;
use construct_db as db;
use construct_error::AppError;
use construct_utils::log_safe_id;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AccountInfoData {
    pub user_id: String,
    pub username: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateAccountInput {
    pub username: Option<String>,
}

pub async fn get_account_info(
    app_context: Arc<AppContext>,
    user_id: Uuid,
) -> Result<AccountInfoData, AppError> {
    let user_record = db::get_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Failed to fetch user from database"
            );
            AppError::Unknown(e)
        })?;

    let user_record = user_record.ok_or_else(|| {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "User not found in database"
        );
        // SECURITY: Don't reveal whether user exists - use generic error
        AppError::Auth("Session is invalid or expired".to_string())
    })?;

    tracing::debug!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Account information retrieved"
    );

    Ok(AccountInfoData {
        user_id: user_record.id.to_string(),
        username: user_record.username,
        created_at: None,
    })
}

pub async fn update_account(
    app_context: Arc<AppContext>,
    user_id: Uuid,
    input: UpdateAccountInput,
) -> Result<(), AppError> {
    // Fetch current user (passwordless)
    let _user_record = db::get_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch user");
            AppError::Unknown(e)
        })?
        .ok_or_else(
            || // SECURITY: Don't reveal whether user exists - use generic error
            AppError::Auth("Session is invalid or expired".to_string()),
        )?;

    // Update username if provided
    if let Some(new_username) = &input.username {
        let normalized = new_username.trim().to_lowercase();
        let username_to_store = if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        };

        if let Some(ref username) = username_to_store {
            if username.len() < 3 || username.len() > 20 {
                return Err(AppError::Validation(
                    "Username must be 3-20 characters".to_string(),
                ));
            }
            if !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(AppError::Validation(
                    "Username can only contain letters, numbers, and underscores".to_string(),
                ));
            }

            if let Ok(Some(existing_user)) =
                db::get_user_by_username(&app_context.db_pool, username).await
                && existing_user.id != user_id
            {
                return Err(AppError::Validation(
                    "Username is already taken".to_string(),
                ));
            }
        }

        db::update_user_username(&app_context.db_pool, &user_id, username_to_store.as_deref())
            .await
            .map_err(AppError::Unknown)?;
        return Ok(());
    }

    // If no updates were requested
    if input.username.is_none() {
        return Err(AppError::Validation(
            "No update fields provided".to_string(),
        ));
    }

    Ok(())
}

