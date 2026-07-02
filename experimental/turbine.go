package experimental

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/turbine"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func NewTurbineGuard(logger log.ContextLogger, options option.TurbineOptions) adapter.ConnectionGuard {
	return turbine.NewGuard(logger, options)
}
