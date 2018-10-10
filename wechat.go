package wechat

import (
  "context"
  "github.com/chone/go-wechat/auth"
)

type App struct {
  appId string
  secret string
}

type Config struct {
  AppId string
  Secret string
}

func NewApp(ctx context.Context, config *Config) (*App, error) {
  return &App{
    appId: config.AppId,
    secret: config.Secret,
  }, nil
}

func (a *App) Auth(ctx context.Context) (*auth.Client, error) {
  conf := &auth.Config{
    AppId: a.appId,
    Secret: a.secret,
  }
  return auth.NewClient(ctx, conf)
}


