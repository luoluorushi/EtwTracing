#include "stdafx.h"



template<typename TController, typename TConsumer>
class CEtwUlt
{
public:
	BOOL run(std::wstring);
	CEtwUlt();

private:
	TController* m_pController;
	TConsumer* m_pConsumer;
};

template<typename TController, typename TConsumer>
CEtwUlt<TController,TConsumer>::CEtwUlt()
{
	m_pController = new TController();
}

template<typename TController, typename TConsumer>
BOOL CEtwUlt<TController,TConsumer>::run(std::wstring programPath)
{
	std::wstring logFilePath;
	DWORD processId = 0;
	if(!m_pController->CtrStartTrace(programPath, logFilePath, &processId))
		return FALSE;

	m_pConsumer = TConsumer::GetInstance();

	if(!m_pConsumer->ParseTraceFile((LPWSTR)logFilePath.c_str(), processId))
		return FALSE;

	return TRUE;
}