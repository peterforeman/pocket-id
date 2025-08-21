package service

import (
	"context"

	"github.com/pocket-id/pocket-id/backend/internal/model"
	"gorm.io/gorm"
)

type CustomScopeService struct {
	db *gorm.DB
}

func NewCustomScopeService(db *gorm.DB) *CustomScopeService {
	return &CustomScopeService{db: db}
}

// GetCustomScopesForUser returns all custom scopes available for a user
func (s *CustomScopeService) GetCustomScopesForUser(ctx context.Context, userID string, tx *gorm.DB) ([]string, error) {
	// Get user's custom claims as potential scopes
	var customClaims []model.CustomClaim
	err := tx.
		WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&customClaims).
		Error
	if err != nil {
		return nil, err
	}

	// Get user groups and their custom claims
	var userGroups []model.UserGroup
	err = tx.
		WithContext(ctx).
		Preload("CustomClaims").
		Joins("JOIN user_groups_users ON user_groups_users.user_group_id = user_groups.id").
		Where("user_groups_users.user_id = ?", userID).
		Find(&userGroups).
		Error
	if err != nil {
		return nil, err
	}

	// Collect all custom claim keys as potential scopes
	scopeSet := make(map[string]struct{})
	
	// Add user's custom claim keys
	for _, claim := range customClaims {
		scopeSet[claim.Key] = struct{}{}
	}
	
	// Add user group custom claim keys
	for _, group := range userGroups {
		for _, claim := range group.CustomClaims {
			scopeSet[claim.Key] = struct{}{}
		}
	}

	// Convert to slice
	scopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// GetAllCustomScopes returns all custom scopes used across the system
func (s *CustomScopeService) GetAllCustomScopes(ctx context.Context) ([]string, error) {
	var customClaimsKeys []string

	err := s.db.
		WithContext(ctx).
		Model(&model.CustomClaim{}).
		Group("key").
		Order("COUNT(*) DESC").
		Pluck("key", &customClaimsKeys).
		Error

	return customClaimsKeys, err
}

// ValidateCustomScopes validates if the requested scopes are available for the user
func (s *CustomScopeService) ValidateCustomScopes(ctx context.Context, userID string, requestedScopes []string, tx *gorm.DB) ([]string, error) {
	availableScopes, err := s.GetCustomScopesForUser(ctx, userID, tx)
	if err != nil {
		return nil, err
	}

	// Standard scopes that are always available
	standardScopes := []string{"openid", "profile", "email", "groups"}
	availableScopes = append(availableScopes, standardScopes...)

	// Filter requested scopes to only include available ones
	validScopes := make([]string, 0)
	for _, requestedScope := range requestedScopes {
		for _, availableScope := range availableScopes {
			if requestedScope == availableScope {
				validScopes = append(validScopes, requestedScope)
				break
			}
		}
	}

	return validScopes, nil
}

