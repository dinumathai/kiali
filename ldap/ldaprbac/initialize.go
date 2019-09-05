package ldaprbac

import (
	"time"
)

func init() {
	SetAccessConfigurationProvider(&accessConfigurationFromCache{})
	go doPeriodicCacheRefresh()
}

func doPeriodicCacheRefresh() {
	for {
		timer1 := time.NewTimer(time.Second * 30)
		<-timer1.C
		refreshLdapRBACCache()
		timer1 = time.NewTimer(time.Minute * 60)
		<-timer1.C
	}
}
